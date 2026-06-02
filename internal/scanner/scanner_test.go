package scanner

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/parth/lastresort/internal/storage"
	"github.com/parth/lastresort/tests/fixtures"
)

func TestActiveScanners(t *testing.T) {
	server := fixtures.NewTargetApp()
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "lastresort-scanner-test-*")
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
	scanID := "scan-active-test"
	_, err = db.ExecContext(ctx, "INSERT INTO scans (id, target_url) VALUES (?, ?)", scanID, server.URL)
	if err != nil {
		t.Fatalf("failed to insert scan: %v", err)
	}

	as := NewActiveScanner(db)

	// 1. Test CORS Scanner on /unsafe-cors
	err = as.ScanCORS(ctx, scanID, server.URL+"/unsafe-cors")
	if err != nil {
		t.Fatalf("ScanCORS failed: %v", err)
	}

	// 2. Test XSS Scanner on /search
	err = as.ScanXSS(ctx, scanID, "GET", server.URL+"/search?q=test", nil, "")
	if err != nil {
		t.Fatalf("ScanXSS failed: %v", err)
	}

	// 3. Test CSRF Scanner on /dashboard POST
	reqHeaders := make(http.Header)
	err = as.ScanCSRF(ctx, scanID, "POST", server.URL+"/dashboard", reqHeaders, []byte("username=admin"), "application/x-www-form-urlencoded")
	if err != nil {
		t.Fatalf("ScanCSRF failed: %v", err)
	}
	res, err := DetectCSRFHeuristic("POST", server.URL+"/dashboard", reqHeaders, []byte("username=admin"), "application/x-www-form-urlencoded")
	if err != nil {
		t.Fatalf("DetectCSRFHeuristic failed: %v", err)
	}
	if res == nil || !res.Suspected {
		t.Fatalf("expected CSRF heuristic to be suspected, got %#v", res)
	}

	// 4. Test Headers passive Scanner on /
	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("failed to get root: %v", err)
	}
	defer resp.Body.Close()
	err = as.ScanHeaders(ctx, scanID, server.URL+"/", resp.Header, resp.StatusCode)
	if err != nil {
		t.Fatalf("ScanHeaders failed: %v", err)
	}

	// 5. Test Rate Limiting on /
	err = as.ScanRateLimit(ctx, scanID, server.URL+"/")
	if err != nil {
		t.Fatalf("ScanRateLimit failed: %v", err)
	}

	// Verify findings in database
	rows, err := db.QueryContext(ctx, "SELECT vulnerability_type, severity FROM findings WHERE scan_id = ?", scanID)
	if err != nil {
		t.Fatalf("failed to query findings: %v", err)
	}
	defer rows.Close()

	findingsMap := make(map[string]string)
	for rows.Next() {
		var vulnType, severity string
		if err := rows.Scan(&vulnType, &severity); err != nil {
			t.Fatalf("failed to scan finding: %v", err)
		}
		findingsMap[vulnType] = severity
	}

	expectedVulns := []string{"CORS Misconfiguration", "Reflected XSS", "Security Misconfiguration", "Rate Limit Testing"}
	for _, ev := range expectedVulns {
		if _, ok := findingsMap[ev]; !ok {
			t.Errorf("expected to find vulnerability type %s, but did not find it in DB: %v", ev, findingsMap)
		}
	}

	if _, ok := findingsMap["CSRF"]; ok {
		t.Fatalf("CSRF must not be saved as a finding without exploit verification")
	}
}
