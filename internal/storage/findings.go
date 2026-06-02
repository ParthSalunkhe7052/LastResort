package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// Finding represents a saved security finding
type Finding struct {
	ID                string  `json:"id"`
	ScanID            string  `json:"scan_id"`
	Title             string  `json:"title"`
	Description       string  `json:"description"`
	Severity          string  `json:"severity"`
	VulnerabilityType string  `json:"vulnerability_type"`
	Endpoint          string  `json:"endpoint"`
	Payload           string  `json:"payload"`
	ResponseStatus    int     `json:"response_status"`
	Confidence        float64 `json:"confidence"`
	IsFalsePositive   int     `json:"is_false_positive"`
	CreatedAt         string  `json:"created_at"`
}

type FindingInput struct {
	ScanID            string
	Title             string
	Description       string
	Severity          string
	VulnerabilityType string
	Endpoint          string
	Payload           string
	ResponseStatus    int
	Confidence        float64
}

// SaveFinding is deprecated and intentionally blocked.
// Findings must never be created without evidence (see SaveFindingWithEvidence).
func (db *DB) SaveFinding(ctx context.Context, scanID, title, description, severity, vulnType, endpoint, payload string, respStatus int, confidence float64) (string, error) {
	_ = ctx
	_ = scanID
	_ = title
	_ = description
	_ = severity
	_ = vulnType
	_ = endpoint
	_ = payload
	_ = respStatus
	_ = confidence
	return "", fmt.Errorf("finding creation without evidence is forbidden; use SaveFindingWithEvidence")
}

// SaveFindingWithEvidence inserts or updates (upserts) a security finding and attaches evidence.
// If evidence is missing, it fails hard.
func (db *DB) SaveFindingWithEvidence(ctx context.Context, in FindingInput, ev EvidenceInput) (string, error) {
	if in.ScanID == "" {
		return "", fmt.Errorf("scanID is required")
	}
	if in.Title == "" {
		return "", fmt.Errorf("title is required")
	}
	if in.Description == "" {
		return "", fmt.Errorf("description is required")
	}
	if in.Severity == "" {
		return "", fmt.Errorf("severity is required")
	}
	if in.VulnerabilityType == "" {
		return "", fmt.Errorf("vulnerability_type is required")
	}
	if in.Endpoint == "" {
		return "", fmt.Errorf("endpoint is required")
	}
	if ev.FlowID <= 0 {
		return "", fmt.Errorf("evidence.flow_id is required")
	}
	if ev.EvidenceType == "" {
		return "", fmt.Errorf("evidence.evidence_type is required")
	}

fp := GenerateFingerprint(in.VulnerabilityType, in.Endpoint, in.Title)

	// Check if a finding with this fingerprint already exists for the scan
	var existingID string
	err := db.QueryRowContext(ctx, "SELECT id FROM findings WHERE scan_id = ? AND fingerprint = ?", in.ScanID, fp).Scan(&existingID)
	if err == nil {
		// Update the existing finding
		_, err = db.ExecContext(ctx,
			`UPDATE findings SET
				description = ?,
				severity = ?,
				payload = ?,
				response_status = ?,
				confidence = ?,
				created_at = CURRENT_TIMESTAMP
			 WHERE id = ?`,
			in.Description, in.Severity, in.Payload, in.ResponseStatus, in.Confidence, existingID,
		)
		if err != nil {
			return "", fmt.Errorf("failed to update finding: %w", err)
		}
		_, _ = db.AddFindingEvidence(ctx, existingID, ev)
		return existingID, nil
	}

	// Insert a new finding
	findingID := uuid.New().String()
	_, err = db.ExecContext(ctx,
		`INSERT INTO findings (id, scan_id, title, description, severity, vulnerability_type, endpoint, payload, response_status, confidence, is_false_positive, fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		findingID, in.ScanID, in.Title, in.Description, in.Severity, in.VulnerabilityType, in.Endpoint, in.Payload, in.ResponseStatus, in.Confidence, fp,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert finding: %w", err)
	}

	if _, err := db.AddFindingEvidence(ctx, findingID, ev); err != nil {
		_, _ = db.ExecContext(ctx, "DELETE FROM findings WHERE id = ?", findingID)
		return "", err
	}
	return findingID, nil
}

