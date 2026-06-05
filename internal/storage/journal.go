package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/parth/lastresort/internal/browser"
)

// JournalEntry represents a single step in an attack workflow.
type JournalEntry struct {
	ID        string                `json:"id"`
	ScanID    string                `json:"scan_id"`
	Step      int                   `json:"step"`
	Action    string                `json:"action"`
	Selector  string                `json:"selector,omitempty"`
	Value     string                `json:"value,omitempty"`
	Success   bool                  `json:"success"`
	Error     string                `json:"error,omitempty"`
	Reasoning string                `json:"reasoning,omitempty"`
	Result    *browser.ActionResult `json:"result,omitempty"`
	CreatedAt time.Time             `json:"created_at"`
}

// CreateJournalTables adds the attack_journal schema.
func (db *DB) CreateJournalTables() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS attack_journal (
		id          TEXT PRIMARY KEY,
		scan_id     TEXT NOT NULL,
		step        INTEGER NOT NULL,
		action      TEXT NOT NULL,
		selector    TEXT,
		value       TEXT,
		success     INTEGER NOT NULL,
		error       TEXT,
		reasoning   TEXT,
		result_json TEXT,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	)`)
	if err != nil {
		return err
	}
	
	// Index for faster history retrieval
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_journal_scan_step ON attack_journal (scan_id, step)`)
	return nil
}

// SaveJournalEntry persists a single attack step.
func (db *DB) SaveJournalEntry(ctx context.Context, entry *JournalEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}

	var resultJSON []byte
	if entry.Result != nil {
		var err error
		resultJSON, err = json.Marshal(entry.Result)
		if err != nil {
			return fmt.Errorf("failed to marshal action result: %w", err)
		}
	}

	successInt := 0
	if entry.Success {
		successInt = 1
	}

	_, err := db.ExecContext(ctx,
		`INSERT INTO attack_journal (id, scan_id, step, action, selector, value, success, error, reasoning, result_json, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.ScanID, entry.Step, entry.Action, entry.Selector, entry.Value, successInt, entry.Error, entry.Reasoning, string(resultJSON), entry.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save journal entry: %w", err)
	}
	return nil
}

// ListJournalEntries returns the full history for a scan.
func (db *DB) ListJournalEntries(ctx context.Context, scanID string) ([]*JournalEntry, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, scan_id, step, action, COALESCE(selector, ''), COALESCE(value, ''), success, COALESCE(error, ''), COALESCE(reasoning, ''), COALESCE(result_json, ''), created_at
		 FROM attack_journal WHERE scan_id = ? ORDER BY step ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*JournalEntry
	for rows.Next() {
		var e JournalEntry
		var resultJSON string
		var successInt int
		if err := rows.Scan(&e.ID, &e.ScanID, &e.Step, &e.Action, &e.Selector, &e.Value, &successInt, &e.Error, &e.Reasoning, &resultJSON, &e.CreatedAt); err != nil {
			continue
		}
		e.Success = successInt == 1
		if resultJSON != "" {
			var res browser.ActionResult
			if err := json.Unmarshal([]byte(resultJSON), &res); err == nil {
				e.Result = &res
			}
		}
		out = append(out, &e)
	}
	return out, nil
}

// GetLastJournalStep returns the highest step number recorded for a scan.
func (db *DB) GetLastJournalStep(ctx context.Context, scanID string) (int, error) {
	var lastStep int
	err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(step), 0) FROM attack_journal WHERE scan_id = ?", scanID).Scan(&lastStep)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	return lastStep, nil
}
