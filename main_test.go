package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackCoreAnalysis)
}

func TestScanFindsGoEndpoints(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	if len(resp.GetFindings()) == 0 {
		t.Fatal("expected at least one finding from Go testdata")
	}

	// Should detect missing auth on /api/admin/users.
	var foundAuth bool
	for _, f := range resp.GetFindings() {
		if f.GetRuleId() == "LOGIC-002" {
			foundAuth = true
		}
	}
	if !foundAuth {
		t.Error("expected LOGIC-002 (missing authorization) finding")
	}
}

func TestScanFindsPythonEndpoints(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	var foundPython bool
	for _, f := range resp.GetFindings() {
		if f.GetMetadata()["language"] == "python" {
			foundPython = true
			break
		}
	}
	if !foundPython {
		t.Error("expected at least one finding from Python testdata")
	}
}

func TestScanFindsJSEndpoints(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	var foundJS bool
	for _, f := range resp.GetFindings() {
		if f.GetMetadata()["language"] == "javascript" {
			foundJS = true
			break
		}
	}
	if !foundJS {
		t.Error("expected at least one finding from JavaScript testdata")
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty workspace, got %d", len(resp.GetFindings()))
	}
}

func TestScanNoWorkspace(t *testing.T) {
	client := testClient(t)
	input, _ := structpb.NewStruct(map[string]any{})
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings without workspace, got %d", len(resp.GetFindings()))
	}
}

func TestScanFindingsHaveMetadata(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	for _, f := range resp.GetFindings() {
		meta := f.GetMetadata()
		if meta["cwe"] == "" {
			t.Errorf("finding %s missing cwe metadata", f.GetRuleId())
		}
		if meta["category"] != "business-logic" {
			t.Errorf("finding %s: expected category business-logic, got %s", f.GetRuleId(), meta["category"])
		}
		if meta["language"] == "" {
			t.Errorf("finding %s missing language metadata", f.GetRuleId())
		}
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, _ := structpb.NewStruct(map[string]any{
		"workspace_root": workspaceRoot,
	})
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}
