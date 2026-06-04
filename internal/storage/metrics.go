package storage

import (
	"context"
	"fmt"
	"time"
)

// AttackMetrics tracks real-time execution counts for a single scan.
// All values are sourced from actual database state — never inferred.
type AttackMetrics struct {
	ScanID          string    `json:"scan_id"`
	AttacksExecuted int       `json:"attacks_executed"`    // total attack attempts (browser executions)
	AttacksVerified int       `json:"attacks_verified"`    // confirmed by verification engine
	AttacksFailed   int       `json:"attacks_failed"`      // executed but verification failed
	AttacksReview   int       `json:"attacks_needs_review"` // unscored / AI uncertain
	UpdatedAt       time.Time `json:"updated_at"`
}

// CreateMetricsTables creates the scan_attack_metrics schema (idempotent).
func (db *DB) CreateMetricsTables() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS scan_attack_metrics (
		scan_id           TEXT PRIMARY KEY,
		attacks_executed  INTEGER NOT NULL DEFAULT 0,
		attacks_verified  INTEGER NOT NULL DEFAULT 0,
		attacks_failed    INTEGER NOT NULL DEFAULT 0,
		attacks_review    INTEGER NOT NULL DEFAULT 0,
		updated_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	)`)
	if err != nil {
		return fmt.Errorf("create scan_attack_metrics table: %w", err)
	}
	return nil
}

// IncrementAttackExecuted atomically increments the executed counter.
func (db *DB) IncrementAttackExecuted(ctx context.Context, scanID string) error {
	return db.upsertMetricDelta(ctx, scanID, "attacks_executed", 1)
}

// IncrementAttackVerified atomically increments the verified counter.
func (db *DB) IncrementAttackVerified(ctx context.Context, scanID string) error {
	return db.upsertMetricDelta(ctx, scanID, "attacks_verified", 1)
}

// IncrementAttackFailed atomically increments the failed counter.
func (db *DB) IncrementAttackFailed(ctx context.Context, scanID string) error {
	return db.upsertMetricDelta(ctx, scanID, "attacks_failed", 1)
}

// IncrementAttackNeedsReview atomically increments the needs-review counter.
func (db *DB) IncrementAttackNeedsReview(ctx context.Context, scanID string) error {
	return db.upsertMetricDelta(ctx, scanID, "attacks_review", 1)
}

// upsertMetricDelta uses INSERT OR REPLACE with COALESCE to safely increment a single column.
func (db *DB) upsertMetricDelta(ctx context.Context, scanID, col string, delta int) error {
	if scanID == "" {
		return fmt.Errorf("scanID required for metric update")
	}
	// Ensure a row exists first, then increment.
	_, err := db.ExecContext(ctx,
		`INSERT INTO scan_attack_metrics (scan_id, attacks_executed, attacks_verified, attacks_failed, attacks_review, updated_at)
		 VALUES (?, 0, 0, 0, 0, CURRENT_TIMESTAMP)
		 ON CONFLICT(scan_id) DO NOTHING`, scanID)
	if err != nil {
		return fmt.Errorf("ensure metrics row: %w", err)
	}

	query := fmt.Sprintf(
		`UPDATE scan_attack_metrics SET %s = COALESCE(%s, 0) + ?, updated_at = CURRENT_TIMESTAMP WHERE scan_id = ?`,
		col, col,
	)
	_, err = db.ExecContext(ctx, query, delta, scanID)
	if err != nil {
		return fmt.Errorf("increment %s: %w", col, err)
	}
	return nil
}

// GetAttackMetrics returns live attack counters for a scan.
func (db *DB) GetAttackMetrics(ctx context.Context, scanID string) (*AttackMetrics, error) {
	m := &AttackMetrics{ScanID: scanID}
	err := db.QueryRowContext(ctx,
		`SELECT attacks_executed, attacks_verified, attacks_failed, attacks_review, updated_at
		 FROM scan_attack_metrics WHERE scan_id = ?`, scanID,
	).Scan(&m.AttacksExecuted, &m.AttacksVerified, &m.AttacksFailed, &m.AttacksReview, &m.UpdatedAt)
	if err != nil {
		// No metrics row yet — return zeroed struct
		m.UpdatedAt = time.Now()
		return m, nil
	}
	return m, nil
}
