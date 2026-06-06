package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGetScanPerformance(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "lastresort-perf-test-*")
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
	scanID := "test-scan-123"

	// 1. Setup minimal scan
	_, err = db.ExecContext(ctx, "INSERT INTO scans (id, target_url, started_at, finished_at) VALUES (?, ?, datetime('now', '-1 minute'), datetime('now'))", scanID, "http://example.com")
	if err != nil {
		t.Fatalf("insert scan failed: %v", err)
	}

	// 2. Setup endpoints (visited pages)
	_, err = db.ExecContext(ctx, "INSERT INTO endpoints (id, scan_id, method, url, source, fingerprint) VALUES ('e1', ?, 'GET', 'http://example.com/a', 'crawler', 'fp-e1')", scanID)
	if err != nil {
		t.Fatalf("insert endpoint 1 failed: %v", err)
	}
	_, err = db.ExecContext(ctx, "INSERT INTO endpoints (id, scan_id, method, url, source, fingerprint) VALUES ('e2', ?, 'GET', 'http://example.com/b', 'crawler', 'fp-e2')", scanID)
	if err != nil {
		t.Fatalf("insert endpoint 2 failed: %v", err)
	}

	// 3. Setup forms
	_, err = db.ExecContext(ctx, "INSERT INTO forms (id, scan_id, url, action, selector) VALUES ('f1', ?, 'http://example.com/a', '/post', '#form1')", scanID)
	if err != nil {
		t.Fatalf("insert form failed: %v", err)
	}

	// 4. Setup attack attempts
	_, err = db.ExecContext(ctx, "INSERT INTO attack_attempts (id, scan_id, attack_type, endpoint, payload, request_captured, result) VALUES ('a1', ?, 'XSS', 'http://example.com/a', '<script>', 'GET...', 'done')", scanID)
	if err != nil {
		t.Fatalf("insert attack_attempt 1 failed: %v", err)
	}
	_, err = db.ExecContext(ctx, "INSERT INTO attack_attempts (id, scan_id, attack_type, endpoint, payload, request_captured, result) VALUES ('a2', ?, 'SQLi', 'http://example.com/b', 'OR 1=1', 'GET...', 'done')", scanID)
	if err != nil {
		t.Fatalf("insert attack_attempt 2 failed: %v", err)
	}

	// 5. Setup findings
	// Verified
	_, err = db.ExecContext(ctx, "INSERT INTO findings (id, scan_id, title, description, category, vulnerability_type, endpoint, severity, fingerprint) VALUES ('f-v', ?, 'V', 'D', 'VERIFIED_FINDING', 'XSS', 'url', 'HIGH', 'fp1')", scanID)
	if err != nil {
		t.Fatalf("insert finding verified failed: %v", err)
	}
	// Potential
	_, err = db.ExecContext(ctx, "INSERT INTO findings (id, scan_id, title, description, category, vulnerability_type, endpoint, severity, fingerprint) VALUES ('f-p', ?, 'P', 'D', 'POTENTIAL_FINDING', 'SQLi', 'url', 'MEDIUM', 'fp2')", scanID)
	if err != nil {
		t.Fatalf("insert finding potential failed: %v", err)
	}
	// Observation
	_, err = db.ExecContext(ctx, "INSERT INTO findings (id, scan_id, title, description, category, vulnerability_type, endpoint, severity, fingerprint) VALUES ('f-o', ?, 'O', 'D', 'OBSERVATION', 'Header', 'url', 'INFO', 'fp3')", scanID)
	if err != nil {
		t.Fatalf("insert finding observation failed: %v", err)
	}

	// Call GetScanPerformance
	metrics, err := db.GetScanPerformance(ctx, scanID)
	if err != nil {
		t.Fatalf("GetScanPerformance failed: %v", err)
	}

	// Assertions
	if metrics.PagesCrawled != 2 {
		t.Errorf("expected 2 pages crawled, got %d", metrics.PagesCrawled)
	}
	if metrics.FormsFound != 1 {
		t.Errorf("expected 1 form found, got %d", metrics.FormsFound)
	}
	if metrics.AttackAttempts != 2 {
		t.Errorf("expected 2 attack attempts (fuzz requests), got %d", metrics.AttackAttempts)
	}
	if metrics.SuccessfulAttacks != 1 {
		t.Errorf("expected 1 successful attack, got %d", metrics.SuccessfulAttacks)
	}
	if metrics.FailedAttempts != 1 {
		t.Errorf("expected 1 failed attempt, got %d", metrics.FailedAttempts)
	}
	if metrics.Observations != 1 {
		t.Errorf("expected 1 observation, got %d", metrics.Observations)
	}
	if metrics.ScanDuration <= 0 {
		t.Errorf("expected positive scan duration, got %f", metrics.ScanDuration)
	}

	// Verify JSON tags
	data, err := json.Marshal(metrics)
	if err != nil {
		t.Fatalf("marshal metrics failed: %v", err)
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		t.Fatalf("unmarshal json failed: %v", err)
	}

	expectedKeys := []string{"visited_pages", "fuzz_requests", "elapsed_seconds"}
	for _, key := range expectedKeys {
		if _, ok := jsonMap[key]; !ok {
			t.Errorf("expected JSON key %q not found in %s", key, string(data))
		}
	}
}
