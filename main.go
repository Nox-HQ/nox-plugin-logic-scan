package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/logic-scan", version).
		Capability("logic-scan", "LLM-assisted business logic flaw detection").
		Tool("scan", "Scan for business logic vulnerabilities: IDOR, broken access control, mass assignment, race conditions", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	resp := sdk.NewResponse()

	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}
	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	aiLogic, _ := req.Input["ai_logic"].(bool)

	// Scan for route handlers and endpoints.
	endpoints := discoverEndpoints(ctx, workspaceRoot)
	if len(endpoints) == 0 {
		return resp.Build(), nil
	}

	// Run deterministic pattern checks.
	deterministicFindings := checkDeterministicPatterns(endpoints)
	for _, f := range deterministicFindings {
		fb := resp.Finding(f.RuleID, f.Severity, f.Confidence, f.Message)
		fb.At(f.FilePath, f.Line, f.Line)
		fb.WithMetadata("cwe", f.CWE)
		fb.WithMetadata("category", "business-logic")
		fb.WithMetadata("language", f.Language)
		fb.WithMetadata("endpoint", f.Endpoint)
		fb.Done()
	}

	// Run AI analysis if enabled.
	if aiLogic && len(endpoints) > 0 {
		provider, model, err := resolveProvider()
		if err != nil {
			built := resp.Build()
			markLogicError(built.GetFindings(), fmt.Sprintf("LLM provider error: %v", err))
			return built, nil
		}

		aiFindings := analyzeWithLLM(ctx, provider, model, endpoints)
		built := resp.Build()
		if aiFindings != nil {
			built.Findings = append(built.Findings, aiFindings...)
		}
		return built, nil
	}

	return resp.Build(), nil
}

// markLogicError adds ai_logic_error metadata to all findings when LLM fails.
func markLogicError(findings []*pluginv1.Finding, errMsg string) {
	for _, f := range findings {
		if f.Metadata == nil {
			f.Metadata = make(map[string]string)
		}
		f.Metadata["ai_logic_error"] = errMsg
	}
}

// discoverEndpoints walks the workspace and finds route handlers.
func discoverEndpoints(ctx context.Context, root string) []Endpoint {
	var endpoints []Endpoint

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		lang := detectLanguage(path)
		if lang == "" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(root, path)
		if relPath == "" {
			relPath = path
		}

		found := extractEndpoints(string(content), relPath, lang)
		endpoints = append(endpoints, found...)
		return nil
	})

	return endpoints
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-logic-scan: %v\n", err)
		return 1
	}
	return 0
}
