package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Report represents a historical scan report.
type Report struct {
	ID        string `json:"id"`
	ScanID    string `json:"scan_id"`
	Format    string `json:"format"`
	Path      string `json:"path"`
	Title     string `json:"title"`
	CreatedAt string `json:"created_at"`
}

// SaveReport records a newly generated report in the database.
func (db *DB) SaveReport(ctx context.Context, scanID, format, path, title string) (string, error) {
	reportID := uuid.New().String()
	_, err := db.ExecContext(ctx,
		`INSERT INTO reports (id, scan_id, format, path, title, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		reportID, scanID, format, path, title, time.Now(),
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert report: %w", err)
	}
	return reportID, nil
}

// GetReport retrieves a single report record by ID.
func (db *DB) GetReport(ctx context.Context, id string) (*Report, error) {
	var r Report
	var createdAt time.Time
	err := db.QueryRowContext(ctx,
		`SELECT id, scan_id, format, path, title, created_at
		 FROM reports WHERE id = ?`, id).Scan(&r.ID, &r.ScanID, &r.Format, &r.Path, &r.Title, &createdAt)

	if err != nil {
		return nil, err
	}
	r.CreatedAt = createdAt.Format(time.RFC3339)
	return &r, nil
}

// ListReports lists all reports for a scan.
func (db *DB) ListReports(ctx context.Context, scanID string) ([]*Report, error) {
	var rows *sql.Rows
	var err error

	if scanID != "" {
		rows, err = db.QueryContext(ctx,
			`SELECT id, scan_id, format, path, title, created_at
			 FROM reports WHERE scan_id = ? ORDER BY created_at DESC`, scanID)
	} else {
		rows, err = db.QueryContext(ctx,
			`SELECT id, scan_id, format, path, title, created_at
			 FROM reports ORDER BY created_at DESC`)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query reports: %w", err)
	}
	defer rows.Close()

	var reports []*Report
	for rows.Next() {
		var r Report
		var createdAt time.Time
		err := rows.Scan(&r.ID, &r.ScanID, &r.Format, &r.Path, &r.Title, &createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan report: %w", err)
		}
		r.CreatedAt = createdAt.Format(time.RFC3339)
		reports = append(reports, &r)
	}

	return reports, nil
}
