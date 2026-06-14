package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	aiv1 "github.com/parth/lastresort/internal/gen/ai/v1"
	scanv1 "github.com/parth/lastresort/internal/gen/scan/v1"
	"github.com/parth/lastresort/internal/orchestrator"
	"github.com/parth/lastresort/internal/storage"
	"github.com/parth/lastresort/tests/fixtures"
)

type mockAiServiceClient struct{}

func (m *mockAiServiceClient) Health(ctx context.Context, req *connect.Request[aiv1.HealthRequest]) (*connect.Response[aiv1.HealthResponse], error) {
	return connect.NewResponse(&aiv1.HealthResponse{
		Status:      "ok",
		Provider:    "mock",
		Model:       "mock-model",
		Initialized: true,
	}), nil
}

func (m *mockAiServiceClient) GenerateExecutiveSummary(ctx context.Context, req *connect.Request[aiv1.GenerateExecutiveSummaryRequest]) (*connect.Response[aiv1.GenerateExecutiveSummaryResponse], error) {
	return connect.NewResponse(&aiv1.GenerateExecutiveSummaryResponse{
		Summary:            "Mock executive summary",
		RiskRating:         "LOW",
		KeyRecommendations: []string{"Keep mock updated"},
	}), nil
}

func (m *mockAiServiceClient) PlanSQLiAttack(ctx context.Context, req *connect.Request[aiv1.PlanSQLiAttackRequest]) (*connect.Response[aiv1.PlanSQLiAttackResponse], error) {
	return connect.NewResponse(&aiv1.PlanSQLiAttackResponse{
		Reasoning: "mock reasoning",
		Payloads: []*aiv1.SQLiPayload{
			{Strategy: "mock", Value: "' OR 1=1 --", Description: "mock description"},
		},
	}), nil
}

func (m *mockAiServiceClient) VerifyAttackResult(ctx context.Context, req *connect.Request[aiv1.VerifyAttackResultRequest]) (*connect.Response[aiv1.VerifyAttackResultResponse], error) {
	return connect.NewResponse(&aiv1.VerifyAttackResultResponse{
		Confirmed:         true,
		Reasoning:         "mock verification reasoning",
		Confidence:        0.95,
		VulnerabilityType: "SQL Injection",
	}), nil
}

func TestStandardScanIntegration(t *testing.T) {
	// 1. Start target application fixture
	targetApp := fixtures.NewTargetApp()
	defer targetApp.Close()

	// 2. Setup clean temporary database
	tmpDir, err := os.MkdirTemp("", "lastresort-integration-test-*")
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

	// 3. Start local mock browser crawler service on port 3010
	l, err := net.Listen("tcp", "127.0.0.1:3010")
	if err != nil {
		t.Fatalf("failed to listen on port 3010: %v. Is another browser service running?", err)
	}

	mockBrowserMux := http.NewServeMux()
	mockBrowserMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	mockBrowserMux.HandleFunc("/crawl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return endpoints & forms discovered in targetApp
		resp := map[string]interface{}{
			"success": true,
			"endpoints": []map[string]interface{}{
				{"method": "GET", "url": targetApp.URL + "/", "source": "crawler"},
				{"method": "GET", "url": targetApp.URL + "/unsafe-cors", "source": "crawler"},
			},
			"forms": []map[string]interface{}{
				{
					"url":      targetApp.URL + "/login",
					"selector": "form",
					"action":   "/dashboard",
					"method":   "POST",
					"inputs": []map[string]interface{}{
						{"text": "", "selector": "input[name=username]", "type": "text", "name": "username"},
						{"text": "", "selector": "input[name=password]", "type": "password", "name": "password"},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	})

	mockBrowserMux.HandleFunc("/action", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"success":          true,
			"screenshotBase64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
			"pageSource":       "<html><body>success lastresort-xss-alert-detected lastresort-ratelimit-results</body></html>",
			"currentUrl":       targetApp.URL + "/dashboard",
			"pageTitle":        "Dashboard",
			"axTree":           "Mock AXTree",
			"links":            []interface{}{},
			"buttons":          []interface{}{},
			"forms":            []interface{}{},
			"cookies":          []interface{}{},
			"localStorage":     map[string]string{},
			"networkEvents":    []interface{}{},
		}
		json.NewEncoder(w).Encode(resp)
	})

	mockBrowserMux.HandleFunc("/end-session", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":true}`)
	})

	mockBrowserServer := httptest.NewUnstartedServer(mockBrowserMux)
	mockBrowserServer.Listener = l
	mockBrowserServer.Start()
	defer mockBrowserServer.Close()

	// 4. Seed scan record
	scanID := "test-integration-scan"
	ctx := context.Background()
	_, err = db.ExecContext(ctx,
		"INSERT INTO scans (id, target_url, status, progress, profile, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		scanID, targetApp.URL, int(scanv1.ScanStatus_SCAN_STATUS_QUEUED), 0.0, int(scanv1.ScanProfile_SCAN_PROFILE_STANDARD), time.Now(),
	)
	if err != nil {
		t.Fatalf("failed to insert mock scan: %v", err)
	}

	// 5. Instantiate Orchestrator and run scan
	aiMock := &mockAiServiceClient{}
	orch := orchestrator.NewOrchestrator(db, aiMock, 8443)
	orch.Start(scanID)

	// 6. Wait for scan completion (max 90 seconds)
	deadline := time.Now().Add(90 * time.Second)
	completed := false
	var status int

	for time.Now().Before(deadline) {
		err = db.QueryRowContext(ctx, "SELECT status FROM scans WHERE id = ?", scanID).Scan(&status)
		if err != nil {
			t.Fatalf("failed to query scan status: %v", err)
		}
		if status == int(scanv1.ScanStatus_SCAN_STATUS_COMPLETED) || status == int(scanv1.ScanStatus_SCAN_STATUS_FAILED) {
			completed = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if !completed {
		t.Fatalf("Scan did not complete within timeout. Current status: %d", status)
	}

	if status != int(scanv1.ScanStatus_SCAN_STATUS_COMPLETED) {
		// Log errors from scan_modules if failed
		rows, err := db.QueryContext(ctx, "SELECT module_name, status, error_message FROM scan_modules WHERE scan_id = ?", scanID)
		if err == nil {
			defer rows.Close()
			t.Log("Module status breakdown:")
			for rows.Next() {
				var name, modStatus, errMsg string
				rows.Scan(&name, &modStatus, &errMsg)
				t.Logf("  - %s: %s (error: %q)", name, modStatus, errMsg)
			}
		}
		t.Fatalf("Expected scan status COMPLETED (4), got %d", status)
	}

	// 7. Verify findings were populated and reports created
	var findingsCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE scan_id = ?", scanID).Scan(&findingsCount)
	if err != nil {
		t.Fatalf("failed to query findings count: %v", err)
	}
	if findingsCount == 0 {
		t.Error("Expected standard scan to discover vulnerability findings, but got 0")
	}

	var reportsCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM reports WHERE scan_id = ?", scanID).Scan(&reportsCount)
	if err != nil {
		t.Fatalf("failed to query reports count: %v", err)
	}
	if reportsCount == 0 {
		t.Error("Expected report record to be created, but got 0")
	}
}
