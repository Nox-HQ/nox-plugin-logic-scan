package main

import (
	"path/filepath"
	"regexp"
	"strings"
)

// detectLanguage returns the language for a file, or empty string if unsupported.
func detectLanguage(path string) string {
	switch filepath.Ext(path) {
	case ".go":
		if strings.HasSuffix(path, "_test.go") {
			return ""
		}
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		if strings.HasSuffix(path, ".d.ts") {
			return ""
		}
		return "typescript"
	}
	return ""
}

// extractEndpoints extracts HTTP route definitions from source code.
func extractEndpoints(content, filePath, lang string) []Endpoint {
	switch lang {
	case "go":
		return extractGoEndpoints(content, filePath)
	case "python":
		return extractPythonEndpoints(content, filePath)
	case "javascript", "typescript":
		return extractJSEndpoints(content, filePath, lang)
	}
	return nil
}

// --- Go extractors ---

var (
	// net/http: http.HandleFunc("/path", handler)
	goHTTPHandleFunc = regexp.MustCompile(`(?:http|mux|r)\.HandleFunc\(\s*"([^"]+)"\s*,\s*(\w+)`)
	// net/http: http.Handle("/path", handler)
	goHTTPHandle = regexp.MustCompile(`(?:http|mux|r)\.Handle\(\s*"([^"]+)"\s*,\s*(\w+)`)
	// gin: r.GET("/path", handler), r.POST(...), etc.
	goGinRoute = regexp.MustCompile(`(?:r|g|router|group|api)\.(?i)(GET|POST|PUT|DELETE|PATCH)\(\s*"([^"]+)"\s*,\s*(?:\w+\.)*(\w+)`)
	// echo: e.GET("/path", handler)
	goEchoRoute = regexp.MustCompile(`(?:e|echo|g|group|api)\.(?i)(GET|POST|PUT|DELETE|PATCH)\(\s*"([^"]+)"\s*,\s*(?:\w+\.)*(\w+)`)
	// fiber: app.Get("/path", handler)
	goFiberRoute = regexp.MustCompile(`(?:app|f|router|group|api)\.(?i)(Get|Post|Put|Delete|Patch)\(\s*"([^"]+)"\s*,\s*(?:\w+\.)*(\w+)`)
	// Auth middleware patterns.
	goAuthMiddleware = regexp.MustCompile(`(?i)(auth|jwt|session|token|middleware\.Auth|requireAuth|Authenticated)`)
)

func extractGoEndpoints(content, filePath string) []Endpoint {
	lines := strings.Split(content, "\n")
	var endpoints []Endpoint

	hasFileAuth := goAuthMiddleware.MatchString(content)

	for lineNum, line := range lines {
		lineNo := lineNum + 1

		if m := goGinRoute.FindStringSubmatch(line); m != nil {
			endpoints = append(endpoints, Endpoint{
				Method:   strings.ToUpper(m[1]),
				Path:     m[2],
				Handler:  m[3],
				FilePath: filePath,
				Line:     lineNo,
				Language: "go",
				Code:     extractHandlerCode(lines, lineNum, content, m[3]),
				HasAuth:  hasFileAuth || hasLocalAuth(lines, lineNum),
			})
		} else if m := goEchoRoute.FindStringSubmatch(line); m != nil {
			endpoints = append(endpoints, Endpoint{
				Method:   strings.ToUpper(m[1]),
				Path:     m[2],
				Handler:  m[3],
				FilePath: filePath,
				Line:     lineNo,
				Language: "go",
				Code:     extractHandlerCode(lines, lineNum, content, m[3]),
				HasAuth:  hasFileAuth || hasLocalAuth(lines, lineNum),
			})
		} else if m := goFiberRoute.FindStringSubmatch(line); m != nil {
			endpoints = append(endpoints, Endpoint{
				Method:   strings.ToUpper(m[1]),
				Path:     m[2],
				Handler:  m[3],
				FilePath: filePath,
				Line:     lineNo,
				Language: "go",
				Code:     extractHandlerCode(lines, lineNum, content, m[3]),
				HasAuth:  hasFileAuth || hasLocalAuth(lines, lineNum),
			})
		} else if m := goHTTPHandleFunc.FindStringSubmatch(line); m != nil {
			endpoints = append(endpoints, Endpoint{
				Method:   "ANY",
				Path:     m[1],
				Handler:  m[2],
				FilePath: filePath,
				Line:     lineNo,
				Language: "go",
				Code:     extractHandlerCode(lines, lineNum, content, m[2]),
				HasAuth:  hasFileAuth || hasLocalAuth(lines, lineNum),
			})
		} else if m := goHTTPHandle.FindStringSubmatch(line); m != nil {
			endpoints = append(endpoints, Endpoint{
				Method:   "ANY",
				Path:     m[1],
				Handler:  m[2],
				FilePath: filePath,
				Line:     lineNo,
				Language: "go",
				Code:     extractHandlerCode(lines, lineNum, content, m[2]),
				HasAuth:  hasFileAuth || hasLocalAuth(lines, lineNum),
			})
		}
	}

	return endpoints
}

// --- Python extractors ---

var (
	// Flask: @app.route("/path", methods=["GET"])
	pyFlaskRoute = regexp.MustCompile(`@(?:app|blueprint|bp)\.route\(\s*["']([^"']+)["'](?:\s*,\s*methods=\[([^\]]+)\])?`)
	// Flask shorthand: @app.get("/path")
	pyFlaskMethod = regexp.MustCompile(`@(?:app|blueprint|bp)\.(get|post|put|delete|patch)\(\s*["']([^"']+)["']`)
	// Django: path("route", view)
	pyDjangoPath = regexp.MustCompile(`path\(\s*["']([^"']+)["']\s*,\s*(\w+)`)
	// FastAPI: @app.get("/path")
	pyFastAPIRoute = regexp.MustCompile(`@(?:app|router)\.(get|post|put|delete|patch)\(\s*["']([^"']+)["']`)
	// Python function def following a decorator.
	pyFuncDef = regexp.MustCompile(`^\s*(?:async\s+)?def\s+(\w+)`)
	// Auth patterns.
	pyAuthPattern = regexp.MustCompile(`(?i)(login_required|auth|permission|jwt|token|@require|authenticate|IsAuthenticated)`)
)

func extractPythonEndpoints(content, filePath string) []Endpoint {
	lines := strings.Split(content, "\n")
	var endpoints []Endpoint

	for lineNum, line := range lines {
		lineNo := lineNum + 1

		var method, path, handler string
		isRoute := false

		if m := pyFastAPIRoute.FindStringSubmatch(line); m != nil {
			method = strings.ToUpper(m[1])
			path = m[2]
			isRoute = true
		} else if m := pyFlaskMethod.FindStringSubmatch(line); m != nil {
			method = strings.ToUpper(m[1])
			path = m[2]
			isRoute = true
		} else if m := pyFlaskRoute.FindStringSubmatch(line); m != nil {
			path = m[1]
			method = extractMethodsFromList(m[2])
			isRoute = true
		} else if m := pyDjangoPath.FindStringSubmatch(line); m != nil {
			path = m[1]
			handler = m[2]
			method = "ANY"
			isRoute = true
		}

		if !isRoute {
			continue
		}

		// Look for the function def after the decorator.
		if handler == "" {
			for j := lineNum + 1; j < len(lines) && j < lineNum+5; j++ {
				if m := pyFuncDef.FindStringSubmatch(lines[j]); m != nil {
					handler = m[1]
					break
				}
			}
		}

		hasAuth := pyAuthPattern.MatchString(content) || hasLocalPyAuth(lines, lineNum)

		endpoints = append(endpoints, Endpoint{
			Method:   method,
			Path:     path,
			Handler:  handler,
			FilePath: filePath,
			Line:     lineNo,
			Language: "python",
			Code:     extractPyHandlerCode(lines, lineNum),
			HasAuth:  hasAuth,
		})
	}

	return endpoints
}

func extractMethodsFromList(methodStr string) string {
	if methodStr == "" {
		return "ANY"
	}
	methodStr = strings.ReplaceAll(methodStr, "'", "")
	methodStr = strings.ReplaceAll(methodStr, "\"", "")
	return strings.TrimSpace(methodStr)
}

// --- JS/TS extractors ---

var (
	// Express: app.get("/path", handler), router.post("/path", handler)
	jsExpressRoute = regexp.MustCompile(`(?:app|router)\.(get|post|put|delete|patch)\(\s*["']([^"']+)["']`)
	// Next.js API routes: export default function handler or export async function GET
	jsNextAPIRoute = regexp.MustCompile(`export\s+(?:default\s+)?(?:async\s+)?function\s+(\w+)`)
	// Auth middleware patterns.
	jsAuthPattern = regexp.MustCompile(`(?i)(auth|jwt|session|passport|authenticate|isAuthenticated|requireAuth|middleware.*auth)`)
)

func extractJSEndpoints(content, filePath, lang string) []Endpoint {
	lines := strings.Split(content, "\n")
	var endpoints []Endpoint

	hasFileAuth := jsAuthPattern.MatchString(content)

	for lineNum, line := range lines {
		lineNo := lineNum + 1

		if m := jsExpressRoute.FindStringSubmatch(line); m != nil {
			endpoints = append(endpoints, Endpoint{
				Method:   strings.ToUpper(m[1]),
				Path:     m[2],
				Handler:  extractJSHandlerName(line),
				FilePath: filePath,
				Line:     lineNo,
				Language: lang,
				Code:     extractJSHandlerCode(lines, lineNum),
				HasAuth:  hasFileAuth || hasLocalJSAuth(lines, lineNum),
			})
		}
	}

	// Detect Next.js API routes from file path.
	if isNextAPIRoute(filePath) {
		for lineNum, line := range lines {
			if m := jsNextAPIRoute.FindStringSubmatch(line); m != nil {
				handler := m[1]
				method := "ANY"
				upper := strings.ToUpper(handler)
				if upper == "GET" || upper == "POST" || upper == "PUT" || upper == "DELETE" || upper == "PATCH" {
					method = upper
				}
				endpoints = append(endpoints, Endpoint{
					Method:   method,
					Path:     filePath,
					Handler:  handler,
					FilePath: filePath,
					Line:     lineNum + 1,
					Language: lang,
					Code:     extractJSHandlerCode(lines, lineNum),
					HasAuth:  hasFileAuth,
				})
			}
		}
	}

	return endpoints
}

func isNextAPIRoute(path string) bool {
	return strings.Contains(path, "/api/") && (strings.HasSuffix(path, "/route.ts") ||
		strings.HasSuffix(path, "/route.js") ||
		strings.Contains(path, "pages/api/"))
}

func extractJSHandlerName(line string) string {
	// Try to extract the handler function name from an Express route.
	parts := strings.Split(line, ",")
	if len(parts) >= 2 {
		handler := strings.TrimSpace(parts[len(parts)-1])
		handler = strings.TrimRight(handler, ");")
		handler = strings.TrimSpace(handler)
		if isIdentifier(handler) {
			return handler
		}
	}
	return "anonymous"
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if i == 0 {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$') {
				return false
			}
		} else {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$') {
				return false
			}
		}
	}
	return true
}

// --- Code extraction helpers ---

func extractHandlerCode(lines []string, routeLine int, fullContent, handlerName string) string {
	// Try to find the handler function in the file.
	funcPattern := regexp.MustCompile(`func\s+` + regexp.QuoteMeta(handlerName) + `\s*\(`)
	for i, line := range lines {
		if funcPattern.MatchString(line) {
			return extractGoFuncBody(lines, i)
		}
	}
	// Fallback: return context around the route registration.
	return extractContext(lines, routeLine, 10)
}

func extractGoFuncBody(lines []string, startLine int) string {
	var sb strings.Builder
	braceDepth := 0
	started := false
	maxLines := 200

	for i := startLine; i < len(lines) && maxLines > 0; i++ {
		sb.WriteString(lines[i])
		sb.WriteByte('\n')
		maxLines--

		braceDepth += strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
		if strings.Contains(lines[i], "{") {
			started = true
		}
		if started && braceDepth <= 0 {
			break
		}
	}
	return sb.String()
}

func extractPyHandlerCode(lines []string, routeLine int) string {
	// Find the def line following the decorator.
	funcStart := -1
	for i := routeLine; i < len(lines) && i < routeLine+5; i++ {
		if pyFuncDef.MatchString(lines[i]) {
			funcStart = i
			break
		}
	}
	if funcStart == -1 {
		return extractContext(lines, routeLine, 10)
	}

	// Extract the indented function body.
	var sb strings.Builder
	sb.WriteString(lines[funcStart])
	sb.WriteByte('\n')

	indent := len(lines[funcStart]) - len(strings.TrimLeft(lines[funcStart], " \t"))
	maxLines := 200

	for i := funcStart + 1; i < len(lines) && maxLines > 0; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || trimmed[0] == '#' {
			sb.WriteString(lines[i])
			sb.WriteByte('\n')
			maxLines--
			continue
		}
		lineIndent := len(lines[i]) - len(strings.TrimLeft(lines[i], " \t"))
		if lineIndent <= indent {
			break
		}
		sb.WriteString(lines[i])
		sb.WriteByte('\n')
		maxLines--
	}
	return sb.String()
}

func extractJSHandlerCode(lines []string, routeLine int) string {
	return extractContext(lines, routeLine, 30)
}

func extractContext(lines []string, centerLine, radius int) string {
	from := centerLine - radius
	if from < 0 {
		from = 0
	}
	to := centerLine + radius
	if to > len(lines) {
		to = len(lines)
	}

	var sb strings.Builder
	for i := from; i < to; i++ {
		sb.WriteString(lines[i])
		sb.WriteByte('\n')
	}
	return sb.String()
}

// --- Auth detection helpers ---

func hasLocalAuth(lines []string, lineNum int) bool {
	// Check a few lines before/after for auth middleware references.
	from := lineNum - 5
	if from < 0 {
		from = 0
	}
	to := lineNum + 3
	if to > len(lines) {
		to = len(lines)
	}
	for i := from; i < to; i++ {
		if goAuthMiddleware.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

func hasLocalPyAuth(lines []string, lineNum int) bool {
	// Check decorators above the route for auth patterns.
	for i := lineNum - 1; i >= 0 && i >= lineNum-5; i-- {
		if pyAuthPattern.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

func hasLocalJSAuth(lines []string, lineNum int) bool {
	// Check the route line itself and preceding middleware chain.
	from := lineNum - 3
	if from < 0 {
		from = 0
	}
	to := lineNum + 1
	if to > len(lines) {
		to = len(lines)
	}
	for i := from; i < to; i++ {
		if jsAuthPattern.MatchString(lines[i]) {
			return true
		}
	}
	return false
}
