package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// WorkflowMemory represents cached navigation/interaction sequences in SQLite
type WorkflowMemory struct {
	ID         string    `json:"id"`
	TargetHost string    `json:"target_host"`
	FlowType   string    `json:"flow_type"` // e.g. "login"
	ActionsJSON string   `json:"actions_json"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// SaveWorkflowMemory persists or updates a workflow sequence in the SQLite database
func (db *DB) SaveWorkflowMemory(ctx context.Context, host, flowType, actionsJSON string) error {
	id := uuid.New().String()

	// Check if already exists for this host + flowType
	var existingID string
	err := db.QueryRowContext(ctx, "SELECT id FROM workflow_memory WHERE target_host = ? AND flow_type = ?", host, flowType).Scan(&existingID)
	if err == nil {
		// Update existing
		_, err = db.ExecContext(ctx,
			"UPDATE workflow_memory SET actions_json = ?, updated_at = ? WHERE id = ?",
			actionsJSON, time.Now(), existingID,
		)
		if err != nil {
			return fmt.Errorf("failed to update workflow memory: %w", err)
		}
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to check existing workflow memory: %w", err)
	}

	// Insert new
	_, err = db.ExecContext(ctx,
		"INSERT INTO workflow_memory (id, target_host, flow_type, actions_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, host, flowType, actionsJSON, time.Now(), time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to insert workflow memory: %w", err)
	}

	return nil
}

// GetWorkflowMemory retrieves the cached workflow sequence for a given host and flowType
func (db *DB) GetWorkflowMemory(ctx context.Context, host, flowType string) (string, error) {
	var actionsJSON string
	err := db.QueryRowContext(ctx, "SELECT actions_json FROM workflow_memory WHERE target_host = ? AND flow_type = ?", host, flowType).Scan(&actionsJSON)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil // Return empty if not found
		}
		return "", fmt.Errorf("failed to query workflow memory: %w", err)
	}
	return actionsJSON, nil
}
