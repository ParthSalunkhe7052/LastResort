package report

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parth/lastresort/internal/storage"
)

func TestGenerateReport(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "lastresort-report-test-*")
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
	scanID := "scan-report-test"

	// Setup scan and findings in db
	_, err = db.ExecContext(ctx, "INSERT INTO scans (id, target_url, status, profile) VALUES (?, ?, 4, 1)", scanID, "http://example.com")
	if err != nil {
		t.Fatalf("failed to insert scan: %v", err)
	}

	flowID := int64(999)

	_, err = db.SaveFindingWithEvidence(ctx, storage.FindingInput{
		ScanID:            scanID,
		Title:             "XSS Vulnerability",
		Description:       "Reflected XSS via q parameter",
		Severity:          "HIGH",
		VulnerabilityType: "Reflected XSS",
		Endpoint:          "http://example.com/search",
		Payload:           "<script>",
		ResponseStatus:    200,
		Confidence:        0.95,
	}, storage.EvidenceInput{
		FlowID:          flowID,
		EvidenceType:    storage.EvidenceHTTPFlow,
		RequestExcerpt:  "GET http://example.com/search?q=test",
		ResponseExcerpt: "<html>ok</html>",
	})
	if err != nil {
		t.Fatalf("failed to save finding: %v", err)
	}

	gen := NewGenerator(db, nil)
	mdPath, htmlPath, err := gen.GenerateScanReport(ctx, scanID)
	if err != nil {
		t.Fatalf("GenerateScanReport failed: %v", err)
	}

	if _, err := os.Stat(mdPath); os.IsNotExist(err) {
		t.Errorf("expected Markdown report file to exist, but it does not: %s", mdPath)
	}

	if _, err := os.Stat(htmlPath); os.IsNotExist(err) {
		t.Errorf("expected HTML report file to exist, but it does not: %s", htmlPath)
	}

	// Verify report contents
	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("failed to read HTML report: %v", err)
	}
	htmlContent := string(htmlBytes)
	if !strings.Contains(htmlContent, "XSS Vulnerability") {
		t.Errorf("HTML report does not contain the finding title 'XSS Vulnerability'")
	}
}
