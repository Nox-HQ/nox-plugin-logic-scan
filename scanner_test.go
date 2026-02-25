package main

import (
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

func TestIsSensitiveRoute(t *testing.T) {
	tests := []struct {
		path   string
		method string
		want   bool
	}{
		{"/api/users/:id", "GET", true},
		{"/api/admin/settings", "GET", true},
		{"/api/v1/items", "POST", true},
		{"/health", "GET", false},
		{"/api/items", "DELETE", true},
		{"/dashboard", "GET", true},
	}

	for _, tt := range tests {
		got := isSensitiveRoute(tt.path, tt.method)
		if got != tt.want {
			t.Errorf("isSensitiveRoute(%q, %q): got %v, want %v", tt.path, tt.method, got, tt.want)
		}
	}
}

func TestHasIDParam(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/api/users/:id", true},
		{"/api/users/{id}", true},
		{"/api/users/<int:id>", true},
		{"/api/users/:user_id", true},
		{"/api/users", false},
		{"/health", false},
	}

	for _, tt := range tests {
		got := hasIDParam(tt.path)
		if got != tt.want {
			t.Errorf("hasIDParam(%q): got %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestHasOwnershipCheck(t *testing.T) {
	tests := []struct {
		code string
		want bool
	}{
		{"if user_id == currentUser.ID {", true},
		{"user := db.Find(id)", false},
		{"if req.user.id != resource.owner_id { return 403 }", true},
		{"return json.Encode(result)", false},
	}

	for i, tt := range tests {
		got := hasOwnershipCheck(tt.code, "go")
		if got != tt.want {
			t.Errorf("hasOwnershipCheck[%d]: got %v, want %v", i, got, tt.want)
		}
	}
}

func TestHasMassAssignment(t *testing.T) {
	tests := []struct {
		code string
		lang string
		want bool
	}{
		{"json.NewDecoder(r.Body).Decode(&user)", "go", true},
		{"json.NewDecoder(r.Body).Decode(&user) // AllowedFields", "go", false},
		{"data = request.get_json()", "python", true},
		{"data = schema.load(request.get_json())", "python", false},
		{"const data = req.body", "javascript", true},
		{"const data = pick(req.body, allowedFields)", "javascript", false},
	}

	for i, tt := range tests {
		got := hasMassAssignment(tt.code, tt.lang)
		if got != tt.want {
			t.Errorf("hasMassAssignment[%d] (%s): got %v, want %v", i, tt.lang, got, tt.want)
		}
	}
}

func TestCheckDeterministicPatterns_MissingAuth(t *testing.T) {
	endpoints := []Endpoint{
		{Method: "POST", Path: "/api/admin/users", Handler: "createUser", HasAuth: false, Language: "go"},
	}

	findings := checkDeterministicPatterns(endpoints)

	var found bool
	for _, f := range findings {
		if f.RuleID == "LOGIC-002" {
			found = true
			if f.CWE != "CWE-862" {
				t.Errorf("expected CWE-862, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Error("expected LOGIC-002 for missing auth on POST /api/admin/users")
	}
}

func TestCheckDeterministicPatterns_IDOR(t *testing.T) {
	endpoints := []Endpoint{
		{
			Method:   "GET",
			Path:     "/api/users/:id",
			Handler:  "getUser",
			HasAuth:  true,
			Language: "go",
			Code:     "user := db.Find(id)\nreturn json.Encode(user)",
		},
	}

	findings := checkDeterministicPatterns(endpoints)

	var found bool
	for _, f := range findings {
		if f.RuleID == "LOGIC-001" {
			found = true
			if f.CWE != "CWE-639" {
				t.Errorf("expected CWE-639, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Error("expected LOGIC-001 for IDOR on /api/users/:id without ownership check")
	}
}

func TestCheckDeterministicPatterns_MassAssignment(t *testing.T) {
	endpoints := []Endpoint{
		{
			Method:   "PUT",
			Path:     "/api/users/:id",
			Handler:  "updateUser",
			HasAuth:  true,
			Language: "go",
			Code:     "json.NewDecoder(r.Body).Decode(&user)\ndb.Save(user)",
		},
	}

	findings := checkDeterministicPatterns(endpoints)

	var found bool
	for _, f := range findings {
		if f.RuleID == "LOGIC-003" {
			found = true
			if f.CWE != "CWE-915" {
				t.Errorf("expected CWE-915, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Error("expected LOGIC-003 for mass assignment")
	}
}

func TestCheckDeterministicPatterns_AuthProtected(t *testing.T) {
	endpoints := []Endpoint{
		{Method: "GET", Path: "/api/items", Handler: "listItems", HasAuth: true, Language: "go"},
	}

	findings := checkDeterministicPatterns(endpoints)

	for _, f := range findings {
		if f.RuleID == "LOGIC-002" {
			t.Error("should not report missing auth when HasAuth is true")
		}
	}
}

func TestParseLogicResponse_Valid(t *testing.T) {
	input := `[{"rule_id":"LOGIC-001","severity":"high","message":"IDOR detected","cwe":"CWE-639","endpoint":"GET /users/:id","reasoning":"No ownership check"}]`
	findings, err := parseLogicResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "LOGIC-001" {
		t.Errorf("expected LOGIC-001, got %s", findings[0].RuleID)
	}
}

func TestParseLogicResponse_Empty(t *testing.T) {
	findings, err := parseLogicResponse("[]")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseLogicResponse_Invalid(t *testing.T) {
	_, err := parseLogicResponse("not json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestConvertLogicFindings(t *testing.T) {
	ai := []aiLogicFinding{
		{RuleID: "LOGIC-001", Severity: "high", Message: "IDOR", CWE: "CWE-639", Endpoint: "GET /users/:id", Reasoning: "test"},
	}

	findings := convertLogicFindings(ai)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].GetRuleId() != "LOGIC-001" {
		t.Errorf("expected LOGIC-001, got %s", findings[0].GetRuleId())
	}
	if findings[0].GetSeverity() != sdk.SeverityHigh {
		t.Errorf("expected HIGH severity, got %v", findings[0].GetSeverity())
	}
	if findings[0].GetMetadata()["ai_analyzed"] != "true" {
		t.Error("expected ai_analyzed metadata")
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  pluginv1.Severity
	}{
		{"critical", sdk.SeverityCritical},
		{"high", sdk.SeverityHigh},
		{"medium", sdk.SeverityMedium},
		{"low", sdk.SeverityLow},
		{"info", sdk.SeverityInfo},
		{"unknown", pluginv1.Severity(0)},
	}

	for _, tt := range tests {
		got := parseSeverity(tt.input)
		if got != tt.want {
			t.Errorf("parseSeverity(%q): got %v, want %v", tt.input, got, tt.want)
		}
	}
}
