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

// ScanModuleRecord is the public representation of a scan_modules row.
type ScanModuleRecord struct {
	ScanID       string  `json:"scan_id"`
	ModuleName   string  `json:"module_name"`
	Status       string  `json:"status"`
	StartedAt    *string `json:"started_at,omitempty"`
	CompletedAt  *string `json:"completed_at,omitempty"`
	ErrorMessage string  `json:"error_message,omitempty"`
}

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
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM scan_modules WHERE scan_id = ? AND status = ?`,
		scanID, string(ModuleFailed),
	).Scan(&count)
	if err == nil {
		return count > 0, nil
	}
	return false, err
}

// ModuleSummary returns counts of SUCCESS and FAILED modules for partial-success detection.
func (db *DB) ModuleSummary(ctx context.Context, scanID string) (successCount, failedCount int, err error) {
	rows, qErr := db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM scan_modules WHERE scan_id = ? GROUP BY status`, scanID)
	if qErr != nil {
		return 0, 0, qErr
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var cnt int
		if sErr := rows.Scan(&status, &cnt); sErr != nil {
			continue
		}
		switch ModuleStatus(status) {
		case ModuleSuccess:
			successCount += cnt
		case ModuleFailed:
			failedCount += cnt
		}
	}
	return successCount, failedCount, nil
}

// ListScanModules returns all module tracking rows for a scan.
func (db *DB) ListScanModules(ctx context.Context, scanID string) ([]ScanModuleRecord, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT scan_id, module_name, status,
		        strftime('%Y-%m-%dT%H:%M:%SZ', started_at),
		        strftime('%Y-%m-%dT%H:%M:%SZ', completed_at),
		        COALESCE(error_message,'')
		 FROM scan_modules WHERE scan_id = ? ORDER BY rowid ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanModuleRecord
	for rows.Next() {
		var r ScanModuleRecord
		var startedAt, completedAt *string
		if sErr := rows.Scan(&r.ScanID, &r.ModuleName, &r.Status, &startedAt, &completedAt, &r.ErrorMessage); sErr != nil {
			continue
		}
		r.StartedAt = startedAt
		r.CompletedAt = completedAt
		out = append(out, r)
	}
	return out, nil
}

