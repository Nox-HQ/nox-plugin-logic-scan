package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	plannerllm "github.com/felixgeelhaar/agent-go/contrib/planner-llm"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

// Endpoint represents a discovered HTTP route handler.
type Endpoint struct {
	Method   string // GET, POST, PUT, DELETE, etc.
	Path     string // route path
	Handler  string // handler function name
	FilePath string // source file
	Line     int    // line number
	Language string // go, python, javascript, typescript
	Code     string // extracted handler code (up to ~200 lines)
	HasAuth  bool   // whether auth middleware is detected
}

// logicFinding represents a deterministic business logic finding.
type logicFinding struct {
	RuleID     string
	Severity   pluginv1.Severity
	Confidence pluginv1.Confidence
	Message    string
	CWE        string
	FilePath   string
	Line       int
	Language   string
	Endpoint   string
}

// checkDeterministicPatterns runs rule-based checks on discovered endpoints.
func checkDeterministicPatterns(endpoints []Endpoint) []logicFinding {
	var findings []logicFinding

	for _, ep := range endpoints {
		// LOGIC-002: Missing authorization — handler with no auth middleware on sensitive routes.
		if !ep.HasAuth && isSensitiveRoute(ep.Path, ep.Method) {
			findings = append(findings, logicFinding{
				RuleID:     "LOGIC-002",
				Severity:   sdk.SeverityHigh,
				Confidence: sdk.ConfidenceMedium,
				Message:    fmt.Sprintf("Missing authorization: %s %s handler '%s' has no auth middleware", ep.Method, ep.Path, ep.Handler),
				CWE:        "CWE-862",
				FilePath:   ep.FilePath,
				Line:       ep.Line,
				Language:   ep.Language,
				Endpoint:   fmt.Sprintf("%s %s", ep.Method, ep.Path),
			})
		}

		// LOGIC-001: IDOR — direct ID parameter usage without ownership check.
		if hasIDParam(ep.Path) && !hasOwnershipCheck(ep.Code, ep.Language) {
			findings = append(findings, logicFinding{
				RuleID:     "LOGIC-001",
				Severity:   sdk.SeverityHigh,
				Confidence: sdk.ConfidenceLow,
				Message:    fmt.Sprintf("Potential IDOR: %s %s uses ID parameter without ownership verification", ep.Method, ep.Path),
				CWE:        "CWE-639",
				FilePath:   ep.FilePath,
				Line:       ep.Line,
				Language:   ep.Language,
				Endpoint:   fmt.Sprintf("%s %s", ep.Method, ep.Path),
			})
		}

		// LOGIC-003: Mass assignment — request body binding without field filtering.
		if (ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH") && hasMassAssignment(ep.Code, ep.Language) {
			findings = append(findings, logicFinding{
				RuleID:     "LOGIC-003",
				Severity:   sdk.SeverityMedium,
				Confidence: sdk.ConfidenceLow,
				Message:    fmt.Sprintf("Potential mass assignment: %s %s binds request body to model without field filtering", ep.Method, ep.Path),
				CWE:        "CWE-915",
				FilePath:   ep.FilePath,
				Line:       ep.Line,
				Language:   ep.Language,
				Endpoint:   fmt.Sprintf("%s %s", ep.Method, ep.Path),
			})
		}
	}

	return findings
}

// isSensitiveRoute detects routes that typically require authorization.
func isSensitiveRoute(path, method string) bool {
	// Write operations are sensitive.
	if method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH" {
		return true
	}

	sensitivePaths := []string{
		"/admin", "/user", "/account", "/profile",
		"/settings", "/dashboard", "/api/v",
	}
	lower := strings.ToLower(path)
	for _, s := range sensitivePaths {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// hasIDParam checks if a route path contains an ID parameter.
func hasIDParam(path string) bool {
	idPatterns := []string{
		":id", "{id}", "<id>", "<int:id>",
		":user_id", "{user_id}", "<user_id>",
		":userId", "{userId}",
	}
	lower := strings.ToLower(path)
	for _, p := range idPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// hasOwnershipCheck looks for patterns indicating the handler verifies resource ownership.
func hasOwnershipCheck(code, lang string) bool {
	lower := strings.ToLower(code)
	ownerPatterns := []string{
		"user_id ==", "userid ==", "owner_id", "ownerid",
		"currentuser", "current_user", "req.user",
		"getuser(", "get_user(", "authorize",
		"forbidden", "403", "unauthorized",
	}
	for _, p := range ownerPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// hasMassAssignment detects request body binding without explicit field selection.
func hasMassAssignment(code, lang string) bool {
	switch lang {
	case "go":
		return strings.Contains(code, "json.NewDecoder") && !strings.Contains(code, "AllowedFields")
	case "python":
		return (strings.Contains(code, "request.get_json()") || strings.Contains(code, "request.json")) &&
			!strings.Contains(code, "schema") && !strings.Contains(code, "validate")
	case "javascript", "typescript":
		return strings.Contains(code, "req.body") &&
			!strings.Contains(code, "pick(") && !strings.Contains(code, "allowedFields") &&
			!strings.Contains(code, "schema") && !strings.Contains(code, "validate")
	}
	return false
}

// --- LLM Analysis ---

const logicScanSystemPrompt = `You are a security expert specializing in business logic vulnerabilities. You analyze HTTP route handlers and detect:

1. IDOR (Insecure Direct Object Reference) — accessing resources without ownership verification
2. Missing Authorization — endpoints without authentication/authorization checks
3. Mass Assignment — binding request bodies to models without field filtering
4. Race Conditions — non-atomic read-modify-write patterns on shared state
5. Privilege Escalation — ability to modify own roles/permissions
6. Broken Access Control — horizontal/vertical access control bypass

For each vulnerability found, provide:
- "rule_id": string (LOGIC-001 through LOGIC-006)
- "severity": string (critical, high, medium, low)
- "message": string (clear description of the vulnerability)
- "cwe": string (e.g., "CWE-639")
- "endpoint": string (HTTP method + path)
- "reasoning": string (why this is a vulnerability)

Respond ONLY with a JSON array. Empty array if no issues found. Do not include text outside the JSON.`

// aiLogicFinding represents a single LLM-detected business logic flaw.
type aiLogicFinding struct {
	RuleID    string `json:"rule_id"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	CWE       string `json:"cwe"`
	Endpoint  string `json:"endpoint"`
	Reasoning string `json:"reasoning"`
}

// analyzeWithLLM sends endpoint info to the LLM for business logic analysis.
func analyzeWithLLM(ctx context.Context, provider plannerllm.Provider, model string, endpoints []Endpoint) []*pluginv1.Finding {
	prompt := buildLogicPrompt(endpoints)

	resp, err := provider.Complete(ctx, plannerllm.CompletionRequest{
		Model: model,
		Messages: []plannerllm.Message{
			{Role: "system", Content: logicScanSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.3,
		MaxTokens:   8192,
	})
	if err != nil {
		log.Printf("logic-scan: LLM call failed: %v", err)
		return nil
	}

	aiFindings, err := parseLogicResponse(resp.Message.Content)
	if err != nil {
		log.Printf("logic-scan: failed to parse LLM response: %v", err)
		return nil
	}

	return convertLogicFindings(aiFindings)
}

// buildLogicPrompt creates the user message with endpoint details.
func buildLogicPrompt(endpoints []Endpoint) string {
	type summary struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		Handler string `json:"handler"`
		File    string `json:"file"`
		HasAuth bool   `json:"has_auth"`
		Code    string `json:"code"`
	}

	summaries := make([]summary, len(endpoints))
	for i, ep := range endpoints {
		code := ep.Code
		if len(code) > 2000 {
			code = code[:2000] + "\n... (truncated)"
		}
		summaries[i] = summary{
			Method:  ep.Method,
			Path:    ep.Path,
			Handler: ep.Handler,
			File:    ep.FilePath,
			HasAuth: ep.HasAuth,
			Code:    code,
		}
	}

	data, _ := json.MarshalIndent(summaries, "", "  ")

	var sb strings.Builder
	fmt.Fprintf(&sb, "Analyze %d HTTP endpoints for business logic vulnerabilities.\n\n", len(endpoints))
	sb.WriteString("## Endpoints\n\n")
	sb.WriteString(string(data))
	return sb.String()
}

// parseLogicResponse extracts findings from the LLM response.
func parseLogicResponse(content string) ([]aiLogicFinding, error) {
	content = strings.TrimSpace(content)

	if strings.HasPrefix(content, "```") {
		lines := strings.Split(content, "\n")
		if len(lines) >= 2 {
			lines = lines[1:]
		}
		if len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[len(lines)-1]), "```") {
			lines = lines[:len(lines)-1]
		}
		content = strings.Join(lines, "\n")
	}

	var findings []aiLogicFinding
	if err := json.Unmarshal([]byte(content), &findings); err != nil {
		return nil, fmt.Errorf("invalid JSON in LLM response: %w", err)
	}
	return findings, nil
}

// convertLogicFindings converts AI findings to proto findings.
func convertLogicFindings(aiFindings []aiLogicFinding) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range aiFindings {
		sev := parseSeverity(f.Severity)
		if sev == pluginv1.Severity(0) {
			sev = sdk.SeverityHigh
		}

		result = append(result, &pluginv1.Finding{
			RuleId:     f.RuleID,
			Severity:   sev,
			Confidence: sdk.ConfidenceMedium,
			Message:    f.Message,
			Metadata: map[string]string{
				"ai_analyzed": "true",
				"category":    "business-logic",
				"cwe":         f.CWE,
				"endpoint":    f.Endpoint,
				"reasoning":   f.Reasoning,
			},
		})
	}
	return result
}

// parseSeverity converts a severity string to the protobuf enum value.
func parseSeverity(s string) pluginv1.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return sdk.SeverityCritical
	case "high":
		return sdk.SeverityHigh
	case "medium":
		return sdk.SeverityMedium
	case "low":
		return sdk.SeverityLow
	case "info":
		return sdk.SeverityInfo
	default:
		return pluginv1.Severity(0)
	}
}
