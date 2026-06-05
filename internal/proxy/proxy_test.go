package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestProxyRedirectHandling(t *testing.T) {
	// 1. Setup Mock Backend Server that returns a redirect
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// 2. Setup Proxy Infrastructure
	tmpDir, _ := os.MkdirTemp("", "lastresort-proxy-redirect-*")
	defer os.RemoveAll(tmpDir)
	dbPath := filepath.Join(tmpDir, "test.db")
	db, _ := storage.InitDB(dbPath)
	defer db.Close()

	// Use port 0 to get a random free port
	p := NewProxyServer(db, nil, 0)
	err := p.Start()
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer p.Stop()

	// Get the actual port assigned
	proxyAddr := p.listener.Addr().String()

	// 3. Send a request through the proxy to the backend redirect endpoint
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// We use the backend URL but the proxy will intercept it
	// Note: For a plain HTTP proxy request, the URL should be absolute
	targetURL := backend.URL + "/redirect"
	req, _ := http.NewRequest("GET", targetURL, nil)
	
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to send request through proxy: %v", err)
	}
	defer resp.Body.Close()

	// 4. Verify that the proxy returned 302 instead of following to 200
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected status 302 (Found) from proxy, got %d. This means the proxy followed the redirect internally!", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != "/target" {
		t.Errorf("expected Location header '/target', got '%s'", location)
	}
}
