package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

func (db *DB) CreateAttacksTables() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS attack_attempts (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		attack_type TEXT NOT NULL,
		endpoint TEXT NOT NULL,
		payload TEXT NOT NULL,
		request_captured TEXT,
		response_captured TEXT,
		evidence_found TEXT,
		result TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	)`)
	if err != nil {
		return fmt.Errorf("create attack_attempts table: %w", err)
	}
	return nil
}

type AttackAttemptInput struct {
	ScanID           string
	AttackType       string
	Endpoint         string
	Payload          string
	RequestCaptured  string
	ResponseCaptured string
	EvidenceFound    string
	Result           string // verified, failed, needs_review, potential, blocked
}

func (db *DB) SaveAttackAttempt(ctx context.Context, in AttackAttemptInput) (string, error) {
	if in.ScanID == "" {
		return "", fmt.Errorf("ScanID is required")
	}
	if in.AttackType == "" {
		return "", fmt.Errorf("AttackType is required")
	}
	if in.Endpoint == "" {
		return "", fmt.Errorf("Endpoint is required")
	}
	if in.Result == "" {
		in.Result = "failed"
	}

	id := uuid.New().String()
	_, err := db.ExecContext(ctx,
		`INSERT INTO attack_attempts (id, scan_id, attack_type, endpoint, payload, request_captured, response_captured, evidence_found, result)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, in.ScanID, in.AttackType, in.Endpoint, in.Payload, in.RequestCaptured, in.ResponseCaptured, in.EvidenceFound, in.Result,
	)
	if err != nil {
		return "", fmt.Errorf("failed to save attack attempt: %w", err)
	}
	return id, nil
}
