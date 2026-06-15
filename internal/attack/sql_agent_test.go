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

func (m *mockAiClient) PlanAttack(ctx context.Context, req *connect.Request[aiv1.PlanAttackRequest]) (*connect.Response[aiv1.PlanAttackResponse], error) {
	return connect.NewResponse(&aiv1.PlanAttackResponse{
		Payloads: []*aiv1.AttackPayload{
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

type mockBrowserExecutor struct {
	err error
}

func (m *mockBrowserExecutor) ExecuteAction(ctx context.Context, req browser.ActionRequest) (*browser.ActionResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &browser.ActionResult{
		Success:    true,
		PageSource: "mock response source",
	}, nil
}

func TestSQLiModulePlanAndExecute(t *testing.T) {
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

	aiClient := &mockAiClient{}
	module := NewSQLiModule(aiClient, scanID)

	surf := scanner.AttackSurface{
		URL:         targetServer.URL + "/search",
		Method:      "GET",
		ContentType: "text/html",
		Point: scanner.InsertionPoint{
			Name: "q",
			Type: scanner.ParamQuery,
		},
	}

	attempts, err := module.Plan(ctx, surf)
	if err != nil {
		t.Fatalf("failed to plan: %v", err)
	}
	if len(attempts) == 0 {
		t.Error("expected attempts to be planned, got 0")
	}

	mockExec := &mockBrowserExecutor{}
	res, err := module.Execute(ctx, mockExec, attempts[0])
	if err != nil {
		t.Fatalf("failed to execute: %v", err)
	}
	if res.RawResult == nil || res.RawResult.PageSource != "mock response source" {
		t.Errorf("unexpected execute response: %+v", res)
	}
}
