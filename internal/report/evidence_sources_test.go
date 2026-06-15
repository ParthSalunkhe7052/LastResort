package report

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parth/lastresort/internal/storage"
)

func TestGenerateReport_MultiSourceEvidence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "lastresort-report-multi-test-*")
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
	scanID := "scan-multi-source-test"

	// 1. Setup scan
	_, err = db.ExecContext(ctx, "INSERT INTO scans (id, target_url, status, profile) VALUES (?, ?, 4, 1)", scanID, "http://example-multi.com")
	if err != nil {
		t.Fatalf("failed to insert scan: %v", err)
	}

	// 2. Finding with Verification Artifacts
	finding1ID := "finding-verification"
	verID := "ver-123"
	artifacts := []storage.EvidenceArtifact{
		{ArtifactType: storage.EvidenceRequest, Content: "VERIFICATION REQUEST CONTENT"},
		{ArtifactType: storage.EvidenceResponse, Content: "VERIFICATION RESPONSE CONTENT"},
	}
	artifactsJSON, _ := json.Marshal(artifacts)

	_, err = db.ExecContext(ctx, 
		`INSERT INTO findings (id, scan_id, title, description, severity, vulnerability_type, endpoint, payload, response_status, confidence, category, verification_id, fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		finding1ID, scanID, "Verified Finding", "Desc", "HIGH", "SQL Injection", "http://example.com/api", "' OR 1=1", 200, 1.0, "VERIFIED_ATTACK", verID, "fp1",
	)
	if err != nil {
		t.Fatalf("failed to insert finding 1: %v", err)
	}

	_, err = db.ExecContext(ctx,
		`INSERT INTO attack_verifications (id, finding_id, scan_id, verified, confidence, method, summary, artifacts_json, endpoint_url, payload, created_at)
		 VALUES (?, ?, ?, 1, 1.0, 'DOM_MARKER', 'Verified via DOM', ?, ?, ?, ?)`,
		verID, finding1ID, scanID, string(artifactsJSON), "http://example.com/api", "' OR 1=1", time.Now(),
	)
	if err != nil {
		t.Fatalf("failed to insert verification: %v", err)
	}

	// 3. Finding with Attack Attempts (Fallback)
	finding2ID := "finding-attempt"
	endpoint2 := "http://example.com/login"
	payload2 := "admin'--"
	_, err = db.ExecContext(ctx, 
		`INSERT INTO findings (id, scan_id, title, description, severity, vulnerability_type, endpoint, payload, response_status, confidence, category, fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		finding2ID, scanID, "Attempt Finding", "Desc", "MEDIUM", "SQL Injection", endpoint2, payload2, 200, 0.5, "HYPOTHESIS", "fp2",
	)
	if err != nil {
		t.Fatalf("failed to insert finding 2: %v", err)
	}

	_, err = db.ExecContext(ctx,
		`INSERT INTO attack_attempts (id, scan_id, attack_type, endpoint, payload, request_captured, response_captured, result)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"att-456", scanID, "SQL Injection", endpoint2, payload2, "ATTEMPT REQUEST CONTENT", "ATTEMPT RESPONSE CONTENT", "potential",
	)
	if err != nil {
		t.Fatalf("failed to insert attack attempt: %v", err)
	}

	// 4. Finding with Attack Replay (Fallback)
	finding3ID := "finding-replay"
	_, err = db.ExecContext(ctx,
		`INSERT INTO findings (id, scan_id, title, description, severity, vulnerability_type, endpoint, payload, response_status, confidence, category, fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		finding3ID, scanID, "Replay Finding", "Desc", "LOW", "CORS", "http://example.com", "*", 200, 0.9, "VERIFIED_ATTACK", "fp3",
	)
	if err != nil {
		t.Fatalf("failed to insert finding 3: %v", err)
	}

	_, err = db.ExecContext(ctx,
		`INSERT INTO attack_replays (id, finding_id, scan_id, vuln_type, target_url, method, payload, steps_json, page_source_snippet, screenshot_b64, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"rep-789", finding3ID, scanID, "CORS", "http://example.com", "GET", "*", "[]", "REPLAY RESPONSE SNIPPET", "REPLAY_SCREENSHOT_B64", time.Now(),
	)
	if err != nil {
		t.Fatalf("failed to insert attack replay: %v", err)
	}

	// 5. Generate Report
	gen := NewGenerator(db, nil)
	mdPath, htmlPath, err := gen.GenerateScanReport(ctx, scanID)
	if err != nil {
		t.Fatalf("GenerateScanReport failed: %v", err)
	}

	mdBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("failed to read MD report: %v", err)
	}
	mdContent := string(mdBytes)

	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("failed to read HTML report: %v", err)
	}
	htmlContent := string(htmlBytes)

	// 6. Assertions
	if !strings.Contains(mdContent, "VERIFICATION REQUEST CONTENT") {
		t.Errorf("Markdown missing verification request content")
	}
	if !strings.Contains(mdContent, "![Screenshot](data:image/png;base64,REPLAY_SCREENSHOT_B64)") {
		t.Errorf("Markdown missing or malformed replay screenshot")
	}

	if !strings.Contains(htmlContent, "VERIFICATION REQUEST CONTENT") {
		t.Errorf("Report missing verification request content")
	}
	if !strings.Contains(htmlContent, "VERIFICATION RESPONSE CONTENT") {
		t.Errorf("Report missing verification response content")
	}
	if !strings.Contains(htmlContent, "ATTEMPT REQUEST CONTENT") {
		t.Errorf("Report missing attempt request content")
	}
	if !strings.Contains(htmlContent, "ATTEMPT RESPONSE CONTENT") {
		t.Errorf("Report missing attempt response content")
	}
	if !strings.Contains(htmlContent, "REPLAY RESPONSE SNIPPET") {
		t.Errorf("Report missing replay response snippet")
	}
	if !strings.Contains(htmlContent, "data:image/png;base64,REPLAY_SCREENSHOT_B64") {
		t.Errorf("Report missing or malformed replay screenshot. Content: %s", htmlContent)
	}
}
