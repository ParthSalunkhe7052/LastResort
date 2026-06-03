package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

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

// UpdateHypothesisStatus transitions a hypothesis through its lifecycle.
func (db *DB) UpdateHypothesisStatus(ctx context.Context, hypothesisID string, status HypothesisStatus) error {
	if hypothesisID == "" {
		return fmt.Errorf("hypothesisID is required")
	}
	_, err := db.ExecContext(ctx,
		`UPDATE hypotheses SET status = ? WHERE id = ?`,
		string(status), hypothesisID,
	)
	return err
}

// ListHypotheses returns all hypotheses for a scan, ordered newest first.
func (db *DB) ListHypotheses(ctx context.Context, scanID string) ([]Hypothesis, error) {
	var rows *sql.Rows
	var err error

	if scanID != "" {
		rows, err = db.QueryContext(ctx,
			`SELECT id, scan_id, title, description, confidence, source, status, created_at
			 FROM hypotheses WHERE scan_id = ? ORDER BY created_at DESC`, scanID)
	} else {
		rows, err = db.QueryContext(ctx,
			`SELECT id, scan_id, title, description, confidence, source, status, created_at
			 FROM hypotheses ORDER BY created_at DESC`)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query hypotheses: %w", err)
	}
	defer rows.Close()

	var hyps []Hypothesis
	for rows.Next() {
		var h Hypothesis
		var createdAt time.Time
		if err := rows.Scan(&h.ID, &h.ScanID, &h.Title, &h.Description, &h.Confidence, &h.Source, &h.Status, &createdAt); err != nil {
			return nil, fmt.Errorf("failed to scan hypothesis: %w", err)
		}
		h.CreatedAt = createdAt.Format(time.RFC3339)
		hyps = append(hyps, h)
	}
	return hyps, nil
}
