package storage

import (
	"context"
	"fmt"
	"time"
)

type ModuleStatus string

const (
	ModulePending ModuleStatus = "PENDING"
	ModuleRunning ModuleStatus = "RUNNING"
	ModuleSuccess ModuleStatus = "SUCCESS"
	ModuleFailed  ModuleStatus = "FAILED"
)

func (db *DB) UpsertScanModule(ctx context.Context, scanID, moduleName string, status ModuleStatus, startedAt, completedAt *time.Time, errorMessage string) error {
	if scanID == "" {
		return fmt.Errorf("scanID is required")
	}
	if moduleName == "" {
		return fmt.Errorf("moduleName is required")
	}
	if status == "" {
		return fmt.Errorf("status is required")
	}

	// Prefer new schema columns; works on a freshly created DB.
	_, err := db.ExecContext(ctx,
		`INSERT INTO scan_modules (scan_id, module_name, status, started_at, completed_at, error_message)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(scan_id, module_name) DO UPDATE SET
		   status = excluded.status,
		   started_at = COALESCE(excluded.started_at, scan_modules.started_at),
		   completed_at = COALESCE(excluded.completed_at, scan_modules.completed_at),
		   error_message = excluded.error_message`,
		scanID, moduleName, string(status), startedAt, completedAt, errorMessage,
	)
	if err == nil {
		return nil
	}

	// Fallback for older schema columns (`module`, `finished_at`, `error`).
	_, err2 := db.ExecContext(ctx,
		`INSERT INTO scan_modules (scan_id, module, status, started_at, finished_at, error)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(scan_id, module) DO UPDATE SET
		   status = excluded.status,
		   started_at = COALESCE(excluded.started_at, scan_modules.started_at),
		   finished_at = COALESCE(excluded.finished_at, scan_modules.finished_at),
		   error = excluded.error`,
		scanID, moduleName, string(status), startedAt, completedAt, errorMessage,
	)
	return err2
}

func (db *DB) AnyModuleFailed(ctx context.Context, scanID string) (bool, error) {
	if scanID == "" {
		return false, fmt.Errorf("scanID is required")
	}

	var count int
	// Try new schema column first.
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM scan_modules WHERE scan_id = ? AND status = ?`,
		scanID, string(ModuleFailed),
	).Scan(&count)
	if err == nil {
		return count > 0, nil
	}
	// Older schema also uses `status`, so the query should still work.
	return false, err
}

