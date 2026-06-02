package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

type HypothesisStatus string

const (
	HypothesisGenerated HypothesisStatus = "GENERATED"
	HypothesisTesting   HypothesisStatus = "TESTING"
	HypothesisVerified  HypothesisStatus = "VERIFIED"
	HypothesisRejected  HypothesisStatus = "REJECTED"
)

type Hypothesis struct {
	ID          string  `json:"id"`
	ScanID      string  `json:"scan_id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
	Source      string  `json:"source"`
	Status      string  `json:"status"`
	CreatedAt   string  `json:"created_at"`
}

func (db *DB) SaveHypothesis(ctx context.Context, scanID, title, description, source string, confidence float64, status HypothesisStatus) (string, error) {
	if scanID == "" {
		return "", fmt.Errorf("scanID is required")
	}
	if title == "" {
		return "", fmt.Errorf("title is required")
	}
	if description == "" {
		return "", fmt.Errorf("description is required")
	}
	if source == "" {
		source = "unknown"
	}
	if status == "" {
		status = HypothesisGenerated
	}

	id := uuid.New().String()
	_, err := db.ExecContext(ctx,
		`INSERT INTO hypotheses (id, scan_id, title, description, confidence, source, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, scanID, title, description, confidence, source, string(status),
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert hypothesis: %w", err)
	}
	return id, nil
}

