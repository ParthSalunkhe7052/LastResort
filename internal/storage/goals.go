package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// GoalType defines the category of adversarial objective.
type GoalType string

const (
	GoalAccessOtherUserData    GoalType = "ACCESS_OTHER_USER_DATA"
	GoalEscalatePrivileges     GoalType = "ESCALATE_PRIVILEGES"
	GoalAccessAdminFunction    GoalType = "ACCESS_ADMIN_FUNCTION"
	GoalBypassSubscription     GoalType = "BYPASS_SUBSCRIPTION"
	GoalExportRestrictedData   GoalType = "EXPORT_RESTRICTED_DATA"
)

// GoalStatus tracks the lifecycle of a goal attempt.
type GoalStatus string

const (
	GoalPending    GoalStatus = "PENDING"
	GoalRunning    GoalStatus = "RUNNING"
	GoalAchieved   GoalStatus = "ACHIEVED"
	GoalFailed     GoalStatus = "FAILED"
	GoalInconclusive GoalStatus = "INCONCLUSIVE"
)

// AttackGoal represents a single adversarial objective for a scan.
type AttackGoal struct {
	ID                string `json:"id"`
	ScanID            string `json:"scan_id"`
	GoalType          string `json:"goal_type"`
	Description       string `json:"description"`
	SuccessCriteria   string `json:"success_criteria"`
	VerificationCriteria string `json:"verification_criteria"`
	Status            string `json:"status"`
	FindingID         string `json:"finding_id,omitempty"` // populated when ACHIEVED
	Notes             string `json:"notes,omitempty"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

// CreateGoalTables adds the Phase 5 attack_goals schema.
func (db *DB) CreateGoalTables() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS attack_goals (
		id                    TEXT PRIMARY KEY,
		scan_id               TEXT NOT NULL,
		goal_type             TEXT NOT NULL,
		description           TEXT NOT NULL,
		success_criteria      TEXT NOT NULL,
		verification_criteria TEXT NOT NULL,
		status                TEXT NOT NULL DEFAULT 'PENDING',
		finding_id            TEXT,
		notes                 TEXT,
		created_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	)`)
	return err
}

// SaveGoal creates a new attack goal for a scan.
func (db *DB) SaveGoal(ctx context.Context, scanID string, goalType GoalType, description, successCriteria, verificationCriteria string) (string, error) {
	if scanID == "" {
		return "", fmt.Errorf("scanID is required")
	}
	if goalType == "" {
		return "", fmt.Errorf("goalType is required")
	}
	if description == "" {
		return "", fmt.Errorf("description is required")
	}

	id := uuid.New().String()
	_, err := db.ExecContext(ctx,
		`INSERT INTO attack_goals (id, scan_id, goal_type, description, success_criteria, verification_criteria, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, scanID, string(goalType), description, successCriteria, verificationCriteria, string(GoalPending),
	)
	if err != nil {
		return "", fmt.Errorf("failed to save goal: %w", err)
	}
	return id, nil
}

// UpdateGoalStatus transitions a goal through its lifecycle.
// findingID and notes are optional (pass "" to skip).
func (db *DB) UpdateGoalStatus(ctx context.Context, goalID string, status GoalStatus, findingID, notes string) error {
	if goalID == "" {
		return fmt.Errorf("goalID is required")
	}
	_, err := db.ExecContext(ctx,
		`UPDATE attack_goals SET status = ?, finding_id = COALESCE(NULLIF(?, ''), finding_id), notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		string(status), findingID, notes, goalID,
	)
	return err
}

// ListGoals returns all attack goals for a scan.
func (db *DB) ListGoals(ctx context.Context, scanID string) ([]AttackGoal, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, scan_id, goal_type, description, success_criteria, verification_criteria, status,
		        COALESCE(finding_id, ''), COALESCE(notes, ''),
		        strftime('%Y-%m-%dT%H:%M:%SZ', created_at),
		        strftime('%Y-%m-%dT%H:%M:%SZ', updated_at)
		 FROM attack_goals WHERE scan_id = ? ORDER BY created_at ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AttackGoal
	for rows.Next() {
		var g AttackGoal
		if err := rows.Scan(&g.ID, &g.ScanID, &g.GoalType, &g.Description, &g.SuccessCriteria, &g.VerificationCriteria, &g.Status, &g.FindingID, &g.Notes, &g.CreatedAt, &g.UpdatedAt); err != nil {
			continue
		}
		out = append(out, g)
	}
	return out, nil
}
