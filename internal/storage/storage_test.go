package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parth/lastresort/internal/browser"
)

func TestStorageInitAndInserts(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "lastresort-storage-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Verify InitDB creates tables by inserting a projects row
	_, err = db.ExecContext(ctx, "INSERT INTO projects (id, name, target_url) VALUES (?, ?, ?)", "p-1", "test-project", "http://localhost")
	if err != nil {
		t.Fatalf("failed to insert project: %v", err)
	}

	// Verify InitDB creates scans table
	_, err = db.ExecContext(ctx, "INSERT INTO scans (id, target_url) VALUES (?, ?)", "scan-1", "http://localhost")
	if err != nil {
		t.Fatalf("failed to insert scan: %v", err)
	}

	// Dummy flow ID (SaveFlow deprecated)
	flowID := int64(1)

	// Test SaveFindingWithEvidence
	findingID, err := db.SaveFindingWithEvidence(ctx, FindingInput{
		ScanID:            "scan-1",
		Title:             "Test Vuln",
		Description:       "Vuln Desc",
		Severity:          "HIGH",
		VulnerabilityType: "XSS",
		Endpoint:          "http://localhost/api",
		Payload:           "<script>",
		ResponseStatus:    200,
		Confidence:        0.9,
	}, EvidenceInput{
		FlowID:          flowID,
		EvidenceType:    EvidenceHTTPFlow,
		RequestExcerpt:  `GET http://localhost/api`,
		ResponseExcerpt: `{"resp":true}`,
	})
	if err != nil {
		t.Fatalf("SaveFindingWithEvidence failed: %v", err)
	}
	if findingID == "" {
		t.Error("expected non-empty finding ID")
	}
}

func TestSaveFindingDeduplicates(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "lastresort-storage-dedupe-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	_, err = db.ExecContext(ctx, "INSERT INTO scans (id, target_url) VALUES (?, ?)", "scan-2", "http://localhost")
	if err != nil {
		t.Fatalf("failed to insert scan: %v", err)
	}

	// Dummy flow ID (SaveFlow deprecated)
	flowID := int64(2)

	// Save finding first time
	id1, err := db.SaveFindingWithEvidence(ctx, FindingInput{
		ScanID:            "scan-2",
		Title:             "Custom Vulnerability",
		Description:       "Desc 1",
		Severity:          "HIGH",
		VulnerabilityType: "Custom",
		Endpoint:          "http://localhost/search",
		Payload:           "<script>",
		ResponseStatus:    200,
		Confidence:        0.8,
	}, EvidenceInput{
		FlowID:          flowID,
		EvidenceType:    EvidenceHTTPFlow,
		RequestExcerpt:  `GET http://localhost/search?q=test`,
		ResponseExcerpt: `ok`,
	})
	if err != nil {
		t.Fatalf("first SaveFindingWithEvidence failed: %v", err)
	}

	// Save same finding second time with different description, confidence, etc.
	id2, err := db.SaveFindingWithEvidence(ctx, FindingInput{
		ScanID:            "scan-2",
		Title:             "Custom Vulnerability",
		Description:       "Desc 2",
		Severity:          "HIGH",
		VulnerabilityType: "Custom",
		Endpoint:          "http://localhost/search",
		Payload:           "<script>",
		ResponseStatus:    200,
		Confidence:        0.95,
	}, EvidenceInput{
		FlowID:          flowID,
		EvidenceType:    EvidenceHTTPFlow,
		RequestExcerpt:  `GET http://localhost/search?q=test`,
		ResponseExcerpt: `ok`,
	})
	if err != nil {
		t.Fatalf("second SaveFindingWithEvidence failed: %v", err)
	}

	if id1 != id2 {
		t.Errorf("expected same ID returned for upsert, got %s and %s", id1, id2)
	}

	// Verify only one finding row exists in the DB
	var count int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE scan_id = ?", "scan-2").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count findings: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 finding row, got %d", count)
	}

	// Verify confidence and description were updated
	var desc string
	var confidence float64
	err = db.QueryRowContext(ctx, "SELECT description, confidence FROM findings WHERE id = ?", id1).Scan(&desc, &confidence)
	if err != nil {
		t.Fatalf("failed to fetch finding details: %v", err)
	}

	if !strings.Contains(desc, "Desc 2") {
		t.Errorf("expected updated description to contain 'Desc 2', got '%s'", desc)
	}
	if confidence != 0.95 {
		t.Errorf("expected updated confidence 0.95, got %f", confidence)
	}
}

func TestSaveFindingWithoutEvidenceFails(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "lastresort-storage-evidence-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	_, err = db.ExecContext(ctx, "INSERT INTO scans (id, target_url) VALUES (?, ?)", "scan-e1", "http://localhost")
	if err != nil {
		t.Fatalf("failed to insert scan: %v", err)
	}

	_, err = db.SaveFinding(ctx, "scan-e1", "No Evidence", "Desc", "LOW", "XSS", "http://localhost", "", 200, 0.5)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestEndpointsPersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "lastresort-endpoints-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	_, err = db.ExecContext(ctx, "INSERT INTO scans (id, target_url) VALUES (?, ?)", "scan-3", "http://localhost")
	if err != nil {
		t.Fatalf("failed to insert scan: %v", err)
	}

	// Save endpoint first time
	id1, err := db.SaveEndpoint(ctx, "scan-3", "GET", "http://localhost/api/users", "crawler", 200, "application/json")
	if err != nil {
		t.Fatalf("failed to save endpoint: %v", err)
	}

	// Save same endpoint (updates it)
	id2, err := db.SaveEndpoint(ctx, "scan-3", "GET", "http://localhost/api/users", "crawler", 304, "application/json")
	if err != nil {
		t.Fatalf("failed to update endpoint: %v", err)
	}

	if id1 != id2 {
		t.Errorf("expected same ID for upsert, got %s and %s", id1, id2)
	}

	// List endpoints
	eps, err := db.ListEndpoints(ctx, "scan-3")
	if err != nil {
		t.Fatalf("failed to list endpoints: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("expected exactly 1 endpoint, got %d", len(eps))
	}
	if eps[0].StatusCode != 304 {
		t.Errorf("expected updated status code 304, got %d", eps[0].StatusCode)
	}
}

func TestAttackJournal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "lastresort-journal-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	scanID := "scan-journal-1"
	_, _ = db.ExecContext(ctx, "INSERT INTO scans (id, target_url) VALUES (?, ?)", scanID, "http://localhost")

	entry := &JournalEntry{
		ScanID:    scanID,
		Step:      1,
		Action:    "click",
		Selector:  "#login-btn",
		Success:   true,
		Reasoning: "Attempting to reach the login page.",
		Result: &browser.ActionResult{
			Success:          true,
			CurrentURL:       "http://localhost/login",
			PageTitle:        "Login Page",
			ScreenshotBase64: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==",
			PageSource:       "<html><body>Test</body></html>",
		},
	}

	if err := db.SaveJournalEntry(ctx, entry); err != nil {
		t.Fatalf("SaveJournalEntry failed: %v", err)
	}

	entries, err := db.ListJournalEntries(ctx, scanID)
	if err != nil {
		t.Fatalf("ListJournalEntries failed: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	retrieved := entries[0]
	if retrieved.Action != "click" || retrieved.Selector != "#login-btn" || retrieved.Reasoning != "Attempting to reach the login page." {
		t.Errorf("retrieved entry mismatch: %+v", retrieved)
	}

	if retrieved.Result == nil || retrieved.Result.CurrentURL != "http://localhost/login" {
		t.Errorf("retrieved result mismatch: %+v", retrieved.Result)
	}

	// Verify optimization: Screenshot and PageSource should be stripped
	if retrieved.Result.ScreenshotBase64 != "" {
		t.Error("expected ScreenshotBase64 to be stripped from journal")
	}
	if retrieved.Result.PageSource != "" {
		t.Error("expected PageSource to be stripped from journal")
	}

	lastStep, err := db.GetLastJournalStep(ctx, scanID)
	if err != nil {
		t.Fatalf("GetLastJournalStep failed: %v", err)
	}
	if lastStep != 1 {
		t.Errorf("expected last step 1, got %d", lastStep)
	}
}

