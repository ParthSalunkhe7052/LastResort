package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ReplayStep represents one atomic action in the attack replay chain.
type ReplayStep struct {
	StepNumber int    `json:"step_number"`
	Action     string `json:"action"`      // navigate | evaluate | click | fill | submit
	URL        string `json:"url,omitempty"`
	Selector   string `json:"selector,omitempty"`
	Value      string `json:"value,omitempty"` // payload string
	Script     string `json:"script,omitempty"` // evaluated JS
	Note       string `json:"note,omitempty"`
}

// AttackReplay stores the exact reproduction path for a verified finding.
// Every field is sourced from actual execution — never synthetic.
type AttackReplay struct {
	ID            string       `json:"id"`
	FindingID     string       `json:"finding_id"`
	ScanID        string       `json:"scan_id"`
	VulnType      string       `json:"vuln_type"`
	TargetURL     string       `json:"target_url"`
	Method        string       `json:"method"`
	Payload       string       `json:"payload"`
	Steps         []ReplayStep `json:"steps"`
	VerifiedAt    time.Time    `json:"verified_at"`
	ScreenshotB64 string       `json:"screenshot_b64,omitempty"`
	PageSourceSnippet string   `json:"page_source_snippet,omitempty"` // first 2000 chars of page source
	CreatedAt     time.Time    `json:"created_at"`
}

// CreateReplayTables creates the attack_replays schema (idempotent).
func (db *DB) CreateReplayTables() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS attack_replays (
		id                   TEXT PRIMARY KEY,
		finding_id           TEXT NOT NULL,
		scan_id              TEXT NOT NULL,
		vuln_type            TEXT NOT NULL,
		target_url           TEXT NOT NULL,
		method               TEXT NOT NULL,
		payload              TEXT,
		steps_json           TEXT NOT NULL,
		verified_at          DATETIME,
		screenshot_b64       TEXT,
		page_source_snippet  TEXT,
		created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	)`)
	if err != nil {
		return fmt.Errorf("create attack_replays table: %w", err)
	}
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_replays_finding ON attack_replays (finding_id)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_replays_scan ON attack_replays (scan_id)`)
	return nil
}

// SaveReplay persists the attack replay path for a verified finding.
// Steps must come from actual browser execution logs — not generated.
func (db *DB) SaveReplay(ctx context.Context, r *AttackReplay) (string, error) {
	if r.FindingID == "" || r.ScanID == "" {
		return "", fmt.Errorf("finding_id and scan_id required")
	}
	if len(r.Steps) == 0 {
		return "", fmt.Errorf("replay steps required (must be from actual execution)")
	}

	stepsJSON, err := json.Marshal(r.Steps)
	if err != nil {
		return "", fmt.Errorf("marshal steps: %w", err)
	}

	if r.ID == "" {
		r.ID = uuid.New().String()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}

	// Truncate page source to avoid storing multi-MB blobs in SQLite
	snippet := r.PageSourceSnippet
	if len(snippet) > 2000 {
		snippet = snippet[:2000] + "...[truncated]"
	}

	_, err = db.ExecContext(ctx,
		`INSERT OR REPLACE INTO attack_replays
			(id, finding_id, scan_id, vuln_type, target_url, method, payload, steps_json, verified_at, screenshot_b64, page_source_snippet, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.FindingID, r.ScanID, r.VulnType, r.TargetURL, r.Method,
		r.Payload, string(stepsJSON), r.VerifiedAt, r.ScreenshotB64, snippet, r.CreatedAt,
	)
	if err != nil {
		return "", fmt.Errorf("insert replay: %w", err)
	}
	return r.ID, nil
}

// GetReplayForFinding returns the replay record for a specific finding.
func (db *DB) GetReplayForFinding(ctx context.Context, findingID string) (*AttackReplay, error) {
	r := &AttackReplay{}
	var stepsJSON string
	err := db.QueryRowContext(ctx,
		`SELECT id, finding_id, scan_id, vuln_type, target_url, method, COALESCE(payload,''),
		        steps_json, COALESCE(screenshot_b64,''), COALESCE(page_source_snippet,''), created_at
		 FROM attack_replays WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1`, findingID,
	).Scan(&r.ID, &r.FindingID, &r.ScanID, &r.VulnType, &r.TargetURL, &r.Method,
		&r.Payload, &stepsJSON, &r.ScreenshotB64, &r.PageSourceSnippet, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(stepsJSON), &r.Steps)
	return r, nil
}

// ListReplaysForScan returns all replays for a scan.
func (db *DB) ListReplaysForScan(ctx context.Context, scanID string) ([]*AttackReplay, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, finding_id, scan_id, vuln_type, target_url, method, COALESCE(payload,''),
		        steps_json, COALESCE(screenshot_b64,''), COALESCE(page_source_snippet,''), created_at
		 FROM attack_replays WHERE scan_id = ? ORDER BY created_at DESC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*AttackReplay
	for rows.Next() {
		r := &AttackReplay{}
		var stepsJSON string
		if err := rows.Scan(&r.ID, &r.FindingID, &r.ScanID, &r.VulnType, &r.TargetURL, &r.Method,
			&r.Payload, &stepsJSON, &r.ScreenshotB64, &r.PageSourceSnippet, &r.CreatedAt); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(stepsJSON), &r.Steps)
		out = append(out, r)
	}
	return out, nil
}
