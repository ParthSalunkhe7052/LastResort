package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

func (m *mockAiServiceClient) CallLLM(ctx context.Context, prompt string, requireJSON bool) (string, error) {
	if requireJSON {
		return `{"thought":"mock thought","action":"finish","finish":true}`, nil
	}
	return "# Mock Manual Hacking Guide\n\nFollow these steps to hack the mock app.", nil
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

	// Seed scan record
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

func TestManualScanIntegration(t *testing.T) {
	// 1. Setup mock tools
	mockDir, err := setupMockTools(t)
	if err != nil {
		t.Fatalf("failed to setup mock tools: %v", err)
	}
	defer os.RemoveAll(mockDir)

	// 2. Start target application fixture
	targetApp := fixtures.NewTargetApp()
	defer targetApp.Close()

	// Add mock tools to PATH
	originalPath := os.Getenv("PATH")
	defer os.Setenv("PATH", originalPath)
	newPath := fmt.Sprintf("%s%c%s", mockDir, os.PathListSeparator, originalPath)
	os.Setenv("PATH", newPath)

	// Set environment variables for mocks
	os.Setenv("TARGET_URL", targetApp.URL)
	os.Setenv("CORSY_PATH", filepath.Join(mockDir, "corsy.py"))
	defer os.Unsetenv("TARGET_URL")
	defer os.Unsetenv("CORSY_PATH")

	// 3. Setup clean temporary database
	tmpDir, err := os.MkdirTemp("", "lastresort-manual-test-*")
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

	// 4. Seed scan record with MANUAL mode
	scanID := "test-manual-scan"
	ctx := context.Background()
	_, err = db.ExecContext(ctx,
		"INSERT INTO scans (id, target_url, status, progress, profile, testing_mode, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		scanID, targetApp.URL, int(scanv1.ScanStatus_SCAN_STATUS_QUEUED), 0.0, int(scanv1.ScanProfile_SCAN_PROFILE_STANDARD), int(scanv1.TestingMode_TESTING_MODE_MANUAL), time.Now(),
	)
	if err != nil {
		t.Fatalf("failed to insert mock scan: %v", err)
	}

	// 5. Instantiate Orchestrator and run scan
	aiMock := &mockAiServiceClient{}
	orch := orchestrator.NewOrchestrator(db, aiMock, 8444) // Different port for safety
	orch.Start(scanID)

	// 6. Wait for scan completion (max 60 seconds)
	deadline := time.Now().Add(60 * time.Second)
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
		time.Sleep(500 * time.Millisecond)
	}

	if !completed {
		t.Fatalf("Manual scan did not complete within timeout. Current status: %d", status)
	}

	if status != int(scanv1.ScanStatus_SCAN_STATUS_COMPLETED) {
		t.Fatalf("Expected manual scan status COMPLETED (4), got %d", status)
	}

	// 7. Verify findings and evidence
	var findingsCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE scan_id = ?", scanID).Scan(&findingsCount)
	if err != nil {
		t.Fatalf("failed to query findings count: %v", err)
	}
	if findingsCount < 3 {
		t.Errorf("Expected manual scan to discover at least 3 findings, but got %d", findingsCount)
	}

	// Verify Katana discovery
	var katanaEndpoints int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM endpoints WHERE scan_id = ? AND source = 'katana-manual'", scanID).Scan(&katanaEndpoints)
	if err != nil {
		t.Fatalf("failed to query katana endpoints: %v", err)
	}
	if katanaEndpoints == 0 {
		t.Error("Expected manual scan to record endpoints from Katana, but got 0")
	}

	// Verify trust labels (finding category should be HYPOTHESIS for manual tools)
	var hypothesisCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE scan_id = ? AND category = 'HYPOTHESIS'", scanID).Scan(&hypothesisCount)
	if err != nil {
		t.Fatalf("failed to query hypothesis count: %v", err)
	}
	if hypothesisCount == 0 {
		t.Error("Expected manual findings to be labeled as HYPOTHESIS, but got 0")
	}

	// Verify Manual Guide Report
	var guideCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM reports WHERE scan_id = ? AND format = 'markdown' AND title = 'Manual Testing Guide'", scanID).Scan(&guideCount)
	if err != nil {
		t.Fatalf("failed to query manual guide report: %v", err)
	}
	if guideCount == 0 {
		t.Error("Expected manual guide report to be created, but got 0")
	}
}

// setupMockTools creates a temporary directory with fake tool binaries.
func setupMockTools(t *testing.T) (string, error) {
	tmpDir, err := os.MkdirTemp("", "mock-tools-*")
	if err != nil {
		return "", err
	}

	tools := []string{"katana", "httpx", "whatweb", "nuclei", "dalfox", "wapiti", "corsy", "corsy.py", "nikto", "sslyze", "ruby", "python", "python3"}

	// We create a universal mock binary that handles various tool output formats.
	mockSource := `
package main

import (
	"fmt"
	"os"
	"strings"
	"io/ioutil"
)

func main() {
	binaryName := os.Args[0]
	if idx := strings.LastIndexAny(binaryName, "/\\"); idx != -1 {
		binaryName = binaryName[idx+1:]
	}
	binaryName = strings.TrimSuffix(binaryName, ".exe")
	binaryName = strings.TrimSuffix(binaryName, ".py")

	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		targetURL = "http://127.0.0.1:8080"
	}
	if !strings.HasSuffix(targetURL, "/") {
		targetURL += "/"
	}

	switch binaryName {
	case "katana":
		for i, arg := range os.Args {
			if arg == "-o" && i+1 < len(os.Args) {
				_ = ioutil.WriteFile(os.Args[i+1], []byte(targetURL+"mock-page-1\n"+targetURL+"mock-page-2\n"), 0644)
			}
		}
	case "httpx":
		fmt.Printf("{\"url\":\"%s\",\"status_code\":200,\"tech\":[\"MockStack\"]}\n", targetURL)
	case "whatweb":
		for _, arg := range os.Args {
			if strings.HasPrefix(arg, "--log-json=") {
				path := strings.TrimPrefix(arg, "--log-json=")
				_ = ioutil.WriteFile(path, []byte("[{\"target\":\""+targetURL+"\",\"plugins\":{\"MockPlugin\":{\"version\":\"1.0\"}}}]"), 0644)
			}
		}
	case "nuclei":
		for i, arg := range os.Args {
			if arg == "-jsonl-export" && i+1 < len(os.Args) {
				_ = ioutil.WriteFile(os.Args[i+1], []byte("{\"template-id\":\"mock-id\",\"info\":{\"name\":\"Mock Nuclei Finding\",\"severity\":\"high\",\"description\":\"Mock description\"},\"host\":\"127.0.0.1\",\"matched-at\":\""+targetURL+"nuclei-vuln\"}\n"), 0644)
			}
		}
	case "dalfox":
		for i, arg := range os.Args {
			if arg == "--output" && i+1 < len(os.Args) {
				_ = ioutil.WriteFile(os.Args[i+1], []byte("[{\"type\":\"VULN\",\"param\":\"q\",\"method\":\"GET\",\"evidence\":\"alert(1)\",\"message\":\"Mock Dalfox Finding\"}]"), 0644)
			}
		}
	case "wapiti":
		for i, arg := range os.Args {
			if arg == "-o" && i+1 < len(os.Args) {
				_ = ioutil.WriteFile(os.Args[i+1], []byte("{\"vulnerabilities\":{\"xss\":[{\"method\":\"GET\",\"path\":\"/wapiti-xss\",\"parameter\":\"q\",\"info\":\"Mock Wapiti XSS\"}]}}"), 0644)
			}
		}
	case "nikto":
		for i, arg := range os.Args {
			if arg == "-o" && i+1 < len(os.Args) {
				_ = ioutil.WriteFile(os.Args[i+1], []byte("{\"vulnerabilities\":[{\"msg\":\"Mock Nikto Finding\",\"url\":\"/nikto-vuln\",\"method\":\"GET\"}]}"), 0644)
			}
		}
	case "sslyze":
		for i, arg := range os.Args {
			if arg == "--json_out" && i+1 < len(os.Args) {
				_ = ioutil.WriteFile(os.Args[i+1], []byte("{\"server_scan_results\":[{\"scan_result\":{\"ssl_scan_result\":{\"is_vulnerable_to_heartbleed\":true}}}]}"), 0644)
			}
		}
	case "ruby", "python", "python3":
		// Just exit success for dependencies
	}

	// Handle version checks for probes
	for _, arg := range os.Args {
		if arg == "-version" || arg == "--version" || arg == "version" {
			if binaryName == "nuclei" {
				fmt.Println("Engine Version: v3.0.0")
			} else if binaryName == "httpx" {
				fmt.Println("httpx ProjectDiscovery v1.0.0")
			} else if binaryName == "dalfox" {
				fmt.Println("dalfox v3.0.0")
			} else if binaryName == "whatweb" {
				fmt.Println("WhatWeb version 1.0.0")
			} else {
				fmt.Println("v1.0.0")
			}
			return
		}
	}
}
`
	srcPath := filepath.Join(tmpDir, "mock_tool.go")
	if err := os.WriteFile(srcPath, []byte(mockSource), 0644); err != nil {
		return "", err
	}

	// Compile the mock tool
	binPath := filepath.Join(tmpDir, "mock_tool")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	
	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to compile mock tool: %v, output: %s", err, string(out))
	}

	// Create symlinks/copies for all tools
	for _, tool := range tools {
		toolPath := filepath.Join(tmpDir, tool)
		if runtime.GOOS == "windows" && !strings.HasSuffix(tool, ".py") {
			toolPath += ".exe"
		}
		
		// Use copy instead of symlink for maximum compatibility across OS/filesystems
		data, err := os.ReadFile(binPath)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(toolPath, data, 0755); err != nil {
			return "", err
		}
	}

	return tmpDir, nil
}
