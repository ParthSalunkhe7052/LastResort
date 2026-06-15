package attack

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/parth/lastresort/internal/browser"
	"github.com/parth/lastresort/internal/scanner"
	"github.com/parth/lastresort/internal/storage"
)

type mockCsrfVerifier struct{}

func (m *mockCsrfVerifier) VerifyCSRF(ctx context.Context, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult {
	return &storage.VerificationResult{
		Verified:        true,
		Confidence:      1.0,
		EvidenceSummary: "Mock CSRF confirmed",
	}
}

func (m *mockCsrfVerifier) VerifyGeneric(ctx context.Context, vulnType, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult {
	return nil
}

func (m *mockCsrfVerifier) VerifyXSS(ctx context.Context, vulnType, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult {
	return nil
}

func (m *mockCsrfVerifier) VerifySQLi(ctx context.Context, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult {
	return nil
}

func (m *mockCsrfVerifier) VerifyPathTraversal(ctx context.Context, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult {
	return nil
}

func (m *mockCsrfVerifier) VerifyRateLimit(ctx context.Context, endpoint, pageSource, screenshotB64 string) *storage.VerificationResult {
	return nil
}

type mockCsrfBrowserExecutor struct{}

func (m *mockCsrfBrowserExecutor) ExecuteAction(ctx context.Context, req browser.ActionRequest) (*browser.ActionResult, error) {
	return &browser.ActionResult{
		Success:    true,
		PageSource: "<html><body>Success</body></html>",
	}, nil
}

func TestCsrfModule(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "csrf_test_*")
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
	scanID := "scan-csrf-test"

	module := NewCsrfModule(nil, scanID)

	surf := scanner.AttackSurface{
		URL:         "http://example.com/update",
		Method:      "POST",
		ContentType: "application/x-www-form-urlencoded",
		BaseBody:    []byte("user=admin&role=user"),
		IsForm:      true,
	}

	attempts, err := module.Plan(ctx, surf)
	if err != nil {
		t.Fatalf("failed to plan: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("expected attempts to be planned, got 0")
	}

	mockExec := &mockCsrfBrowserExecutor{}
	res, err := module.Execute(ctx, mockExec, attempts[0])
	if err != nil {
		t.Fatalf("failed to execute: %v", err)
	}
	if res.RawResult == nil {
		t.Error("expected raw result, got nil")
	}

	verifier := &mockCsrfVerifier{}
	vr, err := module.Verify(ctx, res, verifier)
	if err != nil {
		t.Fatalf("failed to verify: %v", err)
	}
	if !vr.Verified {
		t.Error("expected verified CSRF")
	}

	_, err = db.ExecContext(ctx, "INSERT INTO scans (id, status, target_url) VALUES (?, 'RUNNING', 'http://example.com')", scanID)
	if err != nil {
		t.Fatalf("failed to insert mock scan: %v", err)
	}

	findingID, err := module.Record(ctx, db, attempts[0], res, vr)
	if err != nil {
		t.Fatalf("failed to record: %v", err)
	}
	if findingID == "" {
		t.Error("expected finding ID, got empty")
	}
}
