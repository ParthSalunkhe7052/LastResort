package storage_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/parth/lastresort/internal/storage"
)

// TestPhase2VerificationResult validates the VerificationResult state machine logic.
func TestPhase2VerificationResult(t *testing.T) {
	// Test IsValid() enforcement
	t.Run("VerificationResult_Invalid_NoArtifacts", func(t *testing.T) {
		vr := &storage.VerificationResult{
			Verified:        true,
			Confidence:      0.95,
			Method:          storage.VerificationAlertFired,
			EvidenceSummary: "XSS alert fired",
			// No artifacts
			VerifiedAt: time.Now(),
		}
		if vr.IsValid() {
			t.Error("VerificationResult should be invalid without evidence artifacts")
		}
	})

	t.Run("VerificationResult_Invalid_LowConfidence", func(t *testing.T) {
		vr := &storage.VerificationResult{
			Verified:        true,
			Confidence:      0.5, // below 0.7 threshold
			Method:          storage.VerificationAIScored,
			EvidenceSummary: "AI says maybe",
			EvidenceArtifacts: []storage.EvidenceArtifact{
				{ArtifactType: storage.EvidenceDOM, Label: "DOM", Content: "test"},
			},
			VerifiedAt: time.Now(),
		}
		if vr.IsValid() {
			t.Error("VerificationResult should be invalid with confidence below 0.7")
		}
	})

	t.Run("VerificationResult_Valid", func(t *testing.T) {
		vr := &storage.VerificationResult{
			Verified:        true,
			Confidence:      0.97,
			Method:          storage.VerificationAlertFired,
			EvidenceSummary: "XSS alert fired and DOM marker injected",
			EvidenceArtifacts: []storage.EvidenceArtifact{
				{ArtifactType: storage.EvidenceDOM, Label: "DOM snapshot", Content: "...lastresort-xss-alert-detected..."},
				{ArtifactType: storage.EvidenceScreenshot, Label: "Screenshot", Content: "base64data", ContentEncoding: "base64"},
			},
			EndpointURL: "http://example.com/search?q=test",
			Payload:     "<script>alert(1)</script>",
			VerifiedAt:  time.Now(),
		}
		if !vr.IsValid() {
			t.Error("VerificationResult should be valid")
		}
	})
}

// TestPhase2StorageTables validates that all Phase 2 tables are created successfully.
func TestPhase2StorageTables(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "phase2test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := storage.InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	scanID := "scan-phase2-test"

	// Seed scan row
	_, err = db.ExecContext(ctx, "INSERT INTO scans (id, target_url, status, profile) VALUES (?, ?, 0, 0)", scanID, "http://example.com")
	if err != nil {
		t.Fatalf("Failed to insert scan: %v", err)
	}

	// --- TASK 8: Runtime Metrics ---
	t.Run("Metrics_IncrementAndRead", func(t *testing.T) {
		if err := db.IncrementAttackExecuted(ctx, scanID); err != nil {
			t.Errorf("IncrementAttackExecuted error: %v", err)
		}
		if err := db.IncrementAttackExecuted(ctx, scanID); err != nil {
			t.Errorf("IncrementAttackExecuted 2 error: %v", err)
		}
		if err := db.IncrementAttackVerified(ctx, scanID); err != nil {
			t.Errorf("IncrementAttackVerified error: %v", err)
		}
		if err := db.IncrementAttackFailed(ctx, scanID); err != nil {
			t.Errorf("IncrementAttackFailed error: %v", err)
		}
		if err := db.IncrementAttackNeedsReview(ctx, scanID); err != nil {
			t.Errorf("IncrementAttackNeedsReview error: %v", err)
		}

		metrics, err := db.GetAttackMetrics(ctx, scanID)
		if err != nil {
			t.Fatalf("GetAttackMetrics error: %v", err)
		}
		if metrics.AttacksExecuted != 2 {
			t.Errorf("Expected 2 executed, got %d", metrics.AttacksExecuted)
		}
		if metrics.AttacksVerified != 1 {
			t.Errorf("Expected 1 verified, got %d", metrics.AttacksVerified)
		}
		if metrics.AttacksFailed != 1 {
			t.Errorf("Expected 1 failed, got %d", metrics.AttacksFailed)
		}
		if metrics.AttacksReview != 1 {
			t.Errorf("Expected 1 review, got %d", metrics.AttacksReview)
		}
	})

	// --- TASK 1: Verification Engine ---
	t.Run("Verification_SaveAndRetrieve", func(t *testing.T) {
		// First need a finding to link to
		findingID, err := db.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            scanID,
			Title:             "[AI-VERIFIED] XSS Test",
			Description:       "Test XSS finding for Phase 2",
			Severity:          "HIGH",
			VulnerabilityType: "Reflected XSS",
			Endpoint:          "http://example.com/search",
			Payload:           "<script>alert(1)</script>",
			ResponseStatus:    200,
			Confidence:        0.97,
			Category:          storage.StateVerifiedFinding,
			VerificationID:    "test-verification-id",
		}, storage.EvidenceInput{
			FlowID:          0,
			EvidenceType:    storage.EvidenceScreenshot,
			RequestExcerpt:  "GET /search?q=<script>alert(1)</script> HTTP/1.1\n\n",
			ResponseExcerpt: "...lastresort-xss-alert-detected...",
			ScreenshotB64:   "testbase64",
		})
		if err != nil {
			t.Fatalf("SaveFindingWithEvidence error: %v", err)
		}

		vr := &storage.VerificationResult{
			Verified:        true,
			Confidence:      0.97,
			Method:          storage.VerificationAlertFired,
			EvidenceSummary: "XSS alert fired — DOM marker found",
			EvidenceArtifacts: []storage.EvidenceArtifact{
				{ArtifactType: storage.EvidenceDOM, Label: "DOM", Content: "test"},
			},
			EndpointURL: "http://example.com/search",
			Payload:     "<script>alert(1)</script>",
			VerifiedAt:  time.Now(),
		}

		verID, err := db.SaveVerification(ctx, findingID, scanID, vr)
		if err != nil {
			t.Errorf("SaveVerification error: %v", err)
		}
		if verID == "" {
			t.Error("Expected non-empty verification ID")
		}

		verifications, err := db.ListVerificationsForScan(ctx, scanID)
		if err != nil {
			t.Fatalf("ListVerificationsForScan error: %v", err)
		}
		if len(verifications) == 0 {
			t.Fatal("Expected at least 1 verification")
		}
		sv := verifications[0]
		if !sv.Verified {
			t.Error("Expected verification to be marked verified")
		}
		if sv.Method != storage.VerificationAlertFired {
			t.Errorf("Expected method %s, got %s", storage.VerificationAlertFired, sv.Method)
		}

		// --- TASK 7: Attack Replay ---
		replayID, err := db.SaveReplay(ctx, &storage.AttackReplay{
			FindingID: findingID,
			ScanID:    scanID,
			VulnType:  "Reflected XSS",
			TargetURL: "http://example.com/search",
			Method:    "GET",
			Payload:   "<script>alert(1)</script>",
			Steps: []storage.ReplayStep{
				{StepNumber: 1, Action: "navigate", URL: "http://example.com/search?q=<script>alert(1)</script>", Note: "Navigate with XSS payload"},
			},
			VerifiedAt:        time.Now(),
			PageSourceSnippet: "...xss test page...",
		})
		if err != nil {
			t.Errorf("SaveReplay error: %v", err)
		}
		if replayID == "" {
			t.Error("Expected non-empty replay ID")
		}

		replays, err := db.ListReplaysForScan(ctx, scanID)
		if err != nil {
			t.Fatalf("ListReplaysForScan error: %v", err)
		}
		if len(replays) == 0 {
			t.Fatal("Expected at least 1 replay")
		}
		if len(replays[0].Steps) == 0 {
			t.Error("Expected replay to have steps")
		}
		if replays[0].Steps[0].Action != "navigate" {
			t.Errorf("Expected step action 'navigate', got '%s'", replays[0].Steps[0].Action)
		}
	})

	// --- TASK 5: Finding State Machine ---
	t.Run("StateMachine_ObservationRequiresNoEvidence", func(t *testing.T) {
		_, err := db.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            scanID,
			Title:             "Header observation",
			Description:       "Missing X-Frame-Options",
			Severity:          "LOW",
			VulnerabilityType: "Missing Header",
			Endpoint:          "http://example.com/",
			Confidence:        0.5,
			Category:          storage.StateObservation,
		}, storage.EvidenceInput{
			EvidenceType:   storage.EvidenceHeader,
			RequestExcerpt: "GET / HTTP/1.1",
		})
		if err != nil {
			t.Errorf("StateObservation should save without flow_id: %v", err)
		}
	})

	t.Run("StateMachine_VerifiedFindingRequiresEvidenceContent", func(t *testing.T) {
		_, err := db.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            scanID,
			Title:             "[AI-VERIFIED] Empty evidence finding",
			Description:       "Test",
			Severity:          "HIGH",
			VulnerabilityType: "SQL Injection",
			Endpoint:          "http://example.com/login",
			Confidence:        0.95,
			Category:          storage.StateVerifiedFinding,
		}, storage.EvidenceInput{
			EvidenceType: storage.EvidenceScreenshot,
			// No request, response, or screenshot — should fail
		})
		if err == nil {
			t.Error("StateVerifiedFinding without evidence content should fail")
		}
	})
}
