package attack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/parth/lastresort/internal/browser"
	aiv1 "github.com/parth/lastresort/internal/gen/ai/v1"
	"github.com/parth/lastresort/internal/gen/ai/v1/aiv1connect"
	"github.com/parth/lastresort/internal/storage"
	"github.com/parth/lastresort/internal/scanner"
	"connectrpc.com/connect"
)

type mockAiClient struct {
	aiv1connect.AiServiceClient
}

func (m *mockAiClient) PlanSQLiAttack(ctx context.Context, req *connect.Request[aiv1.PlanSQLiAttackRequest]) (*connect.Response[aiv1.PlanSQLiAttackResponse], error) {
	return connect.NewResponse(&aiv1.PlanSQLiAttackResponse{
		Payloads: []*aiv1.SQLiPayload{
			{Strategy: "error-based", Value: "' OR 1=1 --", Description: "Mock payload"},
		},
		Reasoning: "Mock planning",
	}), nil
}

func (m *mockAiClient) VerifyAttackResult(ctx context.Context, req *connect.Request[aiv1.VerifyAttackResultRequest]) (*connect.Response[aiv1.VerifyAttackResultResponse], error) {
	return connect.NewResponse(&aiv1.VerifyAttackResultResponse{
		Confirmed:         true,
		Reasoning:         "Mock confirmed",
		Confidence:        0.9,
		VulnerabilityType: "SQL Injection",
	}), nil
}

func TestAgentSQLiExecutorGracefulOffline(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "lastresort-agent-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := storage.InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	scanID := "scan-agent-test"
	
	targetMux := http.NewServeMux()
	targetMux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Search Results</body></html>"))
	})
	targetServer := httptest.NewServer(targetMux)
	defer targetServer.Close()

	browserClient := browser.NewClient("http://127.0.0.1:9999") 
	aiClient := &mockAiClient{}

	onLog := func(msg string) {}
	screenshotFn := func(b64 string) {}

	exec := NewAgentSQLiExecutor(db, browserClient, aiClient, scanID, 0, onLog, screenshotFn)

	surf := scanner.AttackSurface{
		URL:         targetServer.URL + "/search",
		Method:      "GET",
		ContentType: "text/html",
		Point: scanner.InsertionPoint{
			Name: "q",
			Type: scanner.ParamQuery,
		},
	}

	err = exec.Execute(ctx, surf)
	if err == nil {
		t.Error("expected Execute to fail because browser service is offline, but it succeeded")
	}
}
