package proxy

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/parth/lastresort/internal/storage"
)

func TestPassiveAnalyzer(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "lastresort-proxy-test-*")
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
	_, err = db.ExecContext(ctx, "INSERT INTO scans (id, target_url) VALUES (?, ?)", "scan-passive-test", "http://localhost")
	if err != nil {
		t.Fatalf("failed to insert scan: %v", err)
	}

	pa := NewPassiveAnalyzer(db)

	// Step 1: Run passive analysis on a mock request missing security headers
	reqHeaders := make(http.Header)
	respHeaders := make(http.Header)
	flowID1, err := db.SaveFlow(ctx, "scan-passive-test", "GET", "http://localhost/", reqHeaders, nil, respHeaders, nil, 200)
	if err != nil {
		t.Fatalf("failed to save flow: %v", err)
	}
	pa.AnalyzeFlow(ctx, "scan-passive-test", flowID1, "GET", "http://localhost/", reqHeaders, respHeaders, 200)

	// Verify missing security header findings were saved
	var count int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE scan_id = ?", "scan-passive-test").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count findings: %v", err)
	}
	if count < 4 {
		t.Errorf("expected at least 4 missing security header findings, got %d", count)
	}

	// Step 2: Test session cookie missing HttpOnly, Secure, SameSite
	respHeaders2 := make(http.Header)
	respHeaders2.Add("Set-Cookie", "sessionid=xyz; Path=/")
	flowID2, err := db.SaveFlow(ctx, "scan-passive-test", "GET", "http://localhost/set-cookie", reqHeaders, nil, respHeaders2, nil, 200)
	if err != nil {
		t.Fatalf("failed to save flow: %v", err)
	}
	pa.AnalyzeFlow(ctx, "scan-passive-test", flowID2, "GET", "http://localhost/set-cookie", reqHeaders, respHeaders2, 200)

	var cookieFindingsCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE scan_id = ? AND vulnerability_type = ?", "scan-passive-test", "Insecure Session Cookie").Scan(&cookieFindingsCount)
	if err != nil {
		t.Fatalf("failed to count cookie findings: %v", err)
	}
	if cookieFindingsCount < 3 {
		t.Errorf("expected 3 insecure session cookie findings (missing HttpOnly, Secure, SameSite), got %d", cookieFindingsCount)
	}

	// Step 3: Test Permissive CORS Configuration
	respHeaders3 := make(http.Header)
	respHeaders3.Set("Access-Control-Allow-Origin", "*")
	respHeaders3.Set("Access-Control-Allow-Credentials", "true")
	flowID3, err := db.SaveFlow(ctx, "scan-passive-test", "GET", "http://localhost/unsafe-cors", reqHeaders, nil, respHeaders3, nil, 200)
	if err != nil {
		t.Fatalf("failed to save flow: %v", err)
	}
	pa.AnalyzeFlow(ctx, "scan-passive-test", flowID3, "GET", "http://localhost/unsafe-cors", reqHeaders, respHeaders3, 200)

	var corsCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE scan_id = ? AND vulnerability_type = ?", "scan-passive-test", "CORS Misconfiguration").Scan(&corsCount)
	if err != nil {
		t.Fatalf("failed to count CORS findings: %v", err)
	}
	if corsCount != 1 {
		t.Errorf("expected 1 CORS misconfiguration finding, got %d", corsCount)
	}
}
