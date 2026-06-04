package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// VerificationMethod enumerates how verification was achieved.
type VerificationMethod string

const (
	VerificationDOMMarker    VerificationMethod = "DOM_MARKER"      // injected element found in DOM
	VerificationAlertFired   VerificationMethod = "ALERT_FIRED"     // JS alert dialog triggered
	VerificationErrorMessage VerificationMethod = "ERROR_MESSAGE"   // DB/system error in response
	VerificationBypass       VerificationMethod = "AUTH_BYPASS"     // access gained without auth
	VerificationStatusCode   VerificationMethod = "STATUS_CHANGE"   // anomalous HTTP status
	VerificationAIScored     VerificationMethod = "AI_SCORED"       // LLM evaluated response
	VerificationTimingAnomaly VerificationMethod = "TIMING_ANOMALY" // time-based detection
	VerificationDataLeak     VerificationMethod = "DATA_LEAK"       // sensitive data in response
	VerificationBurstSuccess VerificationMethod = "BURST_SUCCESS"   // all burst requests succeeded (rate limit)
)

// EvidenceArtifact is a single concrete piece of proof attached to a verification.
type EvidenceArtifact struct {
	ArtifactType    EvidenceType `json:"artifact_type"`   // screenshot, request, response, dom, header
	Label           string       `json:"label"`           // human-readable label
	Content         string       `json:"content"`         // base64 for screenshots, raw text otherwise
	ContentEncoding string       `json:"content_encoding,omitempty"` // "base64" or ""
}

// VerificationResult is the mandatory outcome of every attack verification pass.
// A Finding can only reach state StateVerified if Verified == true and Evidence is non-empty.
type VerificationResult struct {
	// Core verdict
	Verified   bool               `json:"verified"`
	Confidence float64            `json:"confidence"`
	Method     VerificationMethod `json:"method"`

	// Human-readable summary of what was observed
	EvidenceSummary string `json:"evidence_summary"`

	// Concrete artifacts (screenshot, DOM snapshot, request/response pairs)
	EvidenceArtifacts []EvidenceArtifact `json:"evidence_artifacts"`

	// Where the verification happened
	EndpointURL string `json:"endpoint_url"`
	Payload     string `json:"payload"`

	// Timestamps
	VerifiedAt time.Time `json:"verified_at"`
}

// IsValid returns true if the VerificationResult can promote a finding to Verified state.
func (v *VerificationResult) IsValid() bool {
	return v.Verified &&
		v.Confidence > 0.7 &&
		v.Method != "" &&
		v.EvidenceSummary != "" &&
		len(v.EvidenceArtifacts) > 0
}

// StoredVerification is the persisted form of a VerificationResult linked to a finding.
type StoredVerification struct {
	ID          string             `json:"id"`
	FindingID   string             `json:"finding_id"`
	ScanID      string             `json:"scan_id"`
	Verified    bool               `json:"verified"`
	Confidence  float64            `json:"confidence"`
	Method      VerificationMethod `json:"method"`
	Summary     string             `json:"summary"`
	ArtifactsJSON string           `json:"artifacts_json"`
	EndpointURL string             `json:"endpoint_url"`
	Payload     string             `json:"payload"`
	CreatedAt   time.Time          `json:"created_at"`
}

// CreateVerificationTables creates the attack_verifications schema (idempotent).
func (db *DB) CreateVerificationTables() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS attack_verifications (
		id            TEXT PRIMARY KEY,
		finding_id    TEXT NOT NULL,
		scan_id       TEXT NOT NULL,
		verified      INTEGER NOT NULL DEFAULT 0,
		confidence    REAL NOT NULL DEFAULT 0.0,
		method        TEXT NOT NULL,
		summary       TEXT NOT NULL,
		artifacts_json TEXT,
		endpoint_url  TEXT,
		payload       TEXT,
		created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	)`)
	if err != nil {
		return fmt.Errorf("create attack_verifications table: %w", err)
	}
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_verifications_finding ON attack_verifications (finding_id)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_verifications_scan ON attack_verifications (scan_id, verified)`)
	return nil
}

// SaveVerification persists a VerificationResult linked to a finding.
func (db *DB) SaveVerification(ctx context.Context, findingID, scanID string, vr *VerificationResult) (string, error) {
	if findingID == "" {
		return "", fmt.Errorf("findingID required")
	}
	if vr == nil {
		return "", fmt.Errorf("verification result required")
	}

	artifactsJSON, err := json.Marshal(vr.EvidenceArtifacts)
	if err != nil {
		return "", fmt.Errorf("marshal artifacts: %w", err)
	}

	verifiedInt := 0
	if vr.Verified {
		verifiedInt = 1
	}

	id := uuid.New().String()
	_, err = db.ExecContext(ctx,
		`INSERT INTO attack_verifications
			(id, finding_id, scan_id, verified, confidence, method, summary, artifacts_json, endpoint_url, payload, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, findingID, scanID, verifiedInt, vr.Confidence, string(vr.Method),
		vr.EvidenceSummary, string(artifactsJSON), vr.EndpointURL, vr.Payload,
		vr.VerifiedAt,
	)
	if err != nil {
		return "", fmt.Errorf("insert verification: %w", err)
	}
	return id, nil
}

// GetVerificationForFinding retrieves the most recent verification for a finding.
func (db *DB) GetVerificationForFinding(ctx context.Context, findingID string) (*StoredVerification, error) {
	sv := &StoredVerification{}
	err := db.QueryRowContext(ctx,
		`SELECT id, finding_id, scan_id, verified, confidence, method, summary, COALESCE(artifacts_json,'[]'), COALESCE(endpoint_url,''), COALESCE(payload,''), created_at
		 FROM attack_verifications WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1`, findingID,
	).Scan(&sv.ID, &sv.FindingID, &sv.ScanID, &sv.Verified, &sv.Confidence, &sv.Method, &sv.Summary, &sv.ArtifactsJSON, &sv.EndpointURL, &sv.Payload, &sv.CreatedAt)
	if err != nil {
		return nil, err
	}
	return sv, nil
}

// ListVerificationsForScan returns all verifications for a scan.
func (db *DB) ListVerificationsForScan(ctx context.Context, scanID string) ([]*StoredVerification, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, finding_id, scan_id, verified, confidence, method, summary, COALESCE(artifacts_json,'[]'), COALESCE(endpoint_url,''), COALESCE(payload,''), created_at
		 FROM attack_verifications WHERE scan_id = ? ORDER BY created_at DESC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*StoredVerification
	for rows.Next() {
		sv := &StoredVerification{}
		if err := rows.Scan(&sv.ID, &sv.FindingID, &sv.ScanID, &sv.Verified, &sv.Confidence, &sv.Method,
			&sv.Summary, &sv.ArtifactsJSON, &sv.EndpointURL, &sv.Payload, &sv.CreatedAt); err != nil {
			continue
		}
		out = append(out, sv)
	}
	return out, nil
}
