package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// WorkflowState represents a discovered application state (a page/form/view).
type WorkflowState struct {
	ID            string  `json:"id"`
	ScanID        string  `json:"scan_id"`
	URL           string  `json:"url"`
	Method        string  `json:"method"`
	PageTitle     string  `json:"page_title"`
	StatusCode    int     `json:"status_code"`
	ContentType   string  `json:"content_type"`
	AuthContext   string  `json:"auth_context"`   // anonymous, session, admin
	ParamHash     string  `json:"param_hash"`     // fingerprint of query/body params
	ResourceType  string  `json:"resource_type"`  // inferred: login, dashboard, profile, api, etc.
	Fingerprint   string  `json:"fingerprint"`
	FirstSeenAt   string  `json:"first_seen_at"`
}

// WorkflowAction represents a transition between two workflow states.
type WorkflowAction struct {
	ID          string  `json:"id"`
	ScanID      string  `json:"scan_id"`
	FromStateID string  `json:"from_state_id"`
	ToStateID   string  `json:"to_state_id"`
	FlowID      int64   `json:"flow_id"`     // the HTTP flow that caused this transition
	ActionType  string  `json:"action_type"` // form_submit, navigation, xhr, api_call
	Trigger     string  `json:"trigger"`     // what caused the transition (button name, link text)
	CreatedAt   string  `json:"created_at"`
}

// WorkflowArtifact represents a piece of data extracted from a state (IDs, tokens, references).
type WorkflowArtifact struct {
	ID          string `json:"id"`
	ScanID      string `json:"scan_id"`
	StateID     string `json:"state_id"`
	ArtifactType string `json:"artifact_type"` // user_id, resource_id, token, email, uuid
	ParamName   string `json:"param_name"`
	Value       string `json:"value"`
	FoundIn     string `json:"found_in"` // url, body, header, cookie
	CreatedAt   string `json:"created_at"`
}

// WorkflowSession represents an authenticated session context.
type WorkflowSession struct {
	ID          string `json:"id"`
	ScanID      string `json:"scan_id"`
	Role        string `json:"role"`   // anonymous, user, admin
	Username    string `json:"username"`
	Cookies     string `json:"cookies"`     // JSON-encoded cookie jar
	Headers     string `json:"headers"`     // JSON-encoded extra headers (e.g. Authorization)
	Status      string `json:"status"`      // active, expired, invalid
	CreatedAt   string `json:"created_at"`
	LastUsedAt  string `json:"last_used_at"`
}

// CreateWorkflowTables adds the Phase 3 schema to an existing database.
func (db *DB) CreateWorkflowTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS workflow_states (
			id            TEXT PRIMARY KEY,
			scan_id       TEXT NOT NULL,
			url           TEXT NOT NULL,
			method        TEXT NOT NULL DEFAULT 'GET',
			page_title    TEXT NOT NULL DEFAULT '',
			status_code   INTEGER NOT NULL DEFAULT 0,
			content_type  TEXT NOT NULL DEFAULT '',
			auth_context  TEXT NOT NULL DEFAULT 'anonymous',
			param_hash    TEXT NOT NULL DEFAULT '',
			resource_type TEXT NOT NULL DEFAULT 'unknown',
			fingerprint   TEXT NOT NULL,
			first_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
			UNIQUE(scan_id, fingerprint)
		);`,
		`CREATE TABLE IF NOT EXISTS workflow_actions (
			id           TEXT PRIMARY KEY,
			scan_id      TEXT NOT NULL,
			from_state_id TEXT NOT NULL,
			to_state_id   TEXT NOT NULL,
			flow_id       INTEGER NOT NULL,
			action_type   TEXT NOT NULL DEFAULT 'navigation',
			trigger       TEXT NOT NULL DEFAULT '',
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS workflow_artifacts (
			id             TEXT PRIMARY KEY,
			scan_id        TEXT NOT NULL,
			state_id       TEXT NOT NULL,
			artifact_type  TEXT NOT NULL,
			param_name     TEXT NOT NULL,
			value          TEXT NOT NULL,
			found_in       TEXT NOT NULL DEFAULT 'url',
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS workflow_sessions (
			id           TEXT PRIMARY KEY,
			scan_id      TEXT NOT NULL,
			role         TEXT NOT NULL DEFAULT 'anonymous',
			username     TEXT NOT NULL DEFAULT '',
			cookies      TEXT NOT NULL DEFAULT '{}',
			headers      TEXT NOT NULL DEFAULT '{}',
			status       TEXT NOT NULL DEFAULT 'active',
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		);`,
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("workflow table migration failed: %w", err)
		}
	}
	return nil
}

// --- WorkflowState CRUD ---

// SaveWorkflowState upserts a workflow state (deduplicates by fingerprint).
func (db *DB) SaveWorkflowState(ctx context.Context, scanID, urlStr, method, pageTitle, authContext, paramHash, resourceType, fingerprint string, statusCode int, contentType string) (string, error) {
	// Check if already exists.
	var existing string
	err := db.QueryRowContext(ctx,
		`SELECT id FROM workflow_states WHERE scan_id = ? AND fingerprint = ?`, scanID, fingerprint,
	).Scan(&existing)
	if err == nil {
		return existing, nil // already recorded
	}

	id := uuid.New().String()
	_, err = db.ExecContext(ctx,
		`INSERT INTO workflow_states (id, scan_id, url, method, page_title, status_code, content_type, auth_context, param_hash, resource_type, fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, scanID, urlStr, method, pageTitle, statusCode, contentType, authContext, paramHash, resourceType, fingerprint,
	)
	if err != nil {
		return "", fmt.Errorf("failed to save workflow state: %w", err)
	}
	return id, nil
}

// ListWorkflowStates returns all states for a scan.
func (db *DB) ListWorkflowStates(ctx context.Context, scanID string) ([]WorkflowState, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, scan_id, url, method, page_title, status_code, content_type, auth_context, param_hash, resource_type, fingerprint,
		        strftime('%Y-%m-%dT%H:%M:%SZ', first_seen_at)
		 FROM workflow_states WHERE scan_id = ? ORDER BY first_seen_at ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WorkflowState
	for rows.Next() {
		var s WorkflowState
		if err := rows.Scan(&s.ID, &s.ScanID, &s.URL, &s.Method, &s.PageTitle, &s.StatusCode, &s.ContentType, &s.AuthContext, &s.ParamHash, &s.ResourceType, &s.Fingerprint, &s.FirstSeenAt); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

// --- WorkflowAction CRUD ---

// SaveWorkflowAction records a state transition.
func (db *DB) SaveWorkflowAction(ctx context.Context, scanID, fromStateID, toStateID, actionType, trigger string, flowID int64) (string, error) {
	id := uuid.New().String()
	_, err := db.ExecContext(ctx,
		`INSERT INTO workflow_actions (id, scan_id, from_state_id, to_state_id, flow_id, action_type, trigger)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, scanID, fromStateID, toStateID, flowID, actionType, trigger,
	)
	if err != nil {
		return "", fmt.Errorf("failed to save workflow action: %w", err)
	}
	return id, nil
}

// ListWorkflowActions returns all transitions for a scan.
func (db *DB) ListWorkflowActions(ctx context.Context, scanID string) ([]WorkflowAction, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, scan_id, from_state_id, to_state_id, flow_id, action_type, trigger,
		        strftime('%Y-%m-%dT%H:%M:%SZ', created_at)
		 FROM workflow_actions WHERE scan_id = ? ORDER BY created_at ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WorkflowAction
	for rows.Next() {
		var a WorkflowAction
		if err := rows.Scan(&a.ID, &a.ScanID, &a.FromStateID, &a.ToStateID, &a.FlowID, &a.ActionType, &a.Trigger, &a.CreatedAt); err != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

// --- WorkflowArtifact CRUD ---

// SaveWorkflowArtifact stores an extracted value (resource ID, token, etc.) from a state.
func (db *DB) SaveWorkflowArtifact(ctx context.Context, scanID, stateID, artifactType, paramName, value, foundIn string) (string, error) {
	id := uuid.New().String()
	_, err := db.ExecContext(ctx,
		`INSERT OR IGNORE INTO workflow_artifacts (id, scan_id, state_id, artifact_type, param_name, value, found_in)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, scanID, stateID, artifactType, paramName, value, foundIn,
	)
	if err != nil {
		return "", fmt.Errorf("failed to save workflow artifact: %w", err)
	}
	return id, nil
}

// ListWorkflowArtifacts returns all extracted artifacts for a scan.
func (db *DB) ListWorkflowArtifacts(ctx context.Context, scanID string) ([]WorkflowArtifact, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, scan_id, state_id, artifact_type, param_name, value, found_in,
		        strftime('%Y-%m-%dT%H:%M:%SZ', created_at)
		 FROM workflow_artifacts WHERE scan_id = ? ORDER BY created_at ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WorkflowArtifact
	for rows.Next() {
		var a WorkflowArtifact
		if err := rows.Scan(&a.ID, &a.ScanID, &a.StateID, &a.ArtifactType, &a.ParamName, &a.Value, &a.FoundIn, &a.CreatedAt); err != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

// --- WorkflowSession CRUD ---

// SaveWorkflowSession stores an authenticated session configuration.
func (db *DB) SaveWorkflowSession(ctx context.Context, scanID, role, username, cookiesJSON, headersJSON string) (string, error) {
	id := uuid.New().String()
	_, err := db.ExecContext(ctx,
		`INSERT INTO workflow_sessions (id, scan_id, role, username, cookies, headers, status)
		 VALUES (?, ?, ?, ?, ?, ?, 'active')`,
		id, scanID, role, username, cookiesJSON, headersJSON,
	)
	if err != nil {
		return "", fmt.Errorf("failed to save workflow session: %w", err)
	}
	return id, nil
}

// UpdateWorkflowSessionStatus marks a session as expired or invalid.
func (db *DB) UpdateWorkflowSessionStatus(ctx context.Context, sessionID, status string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE workflow_sessions SET status = ?, last_used_at = ? WHERE id = ?`,
		status, time.Now(), sessionID,
	)
	return err
}

// ListWorkflowSessions returns all sessions for a scan.
func (db *DB) ListWorkflowSessions(ctx context.Context, scanID string) ([]WorkflowSession, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, scan_id, role, username, cookies, headers, status,
		        strftime('%Y-%m-%dT%H:%M:%SZ', created_at),
		        strftime('%Y-%m-%dT%H:%M:%SZ', last_used_at)
		 FROM workflow_sessions WHERE scan_id = ? ORDER BY created_at ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WorkflowSession
	for rows.Next() {
		var s WorkflowSession
		if err := rows.Scan(&s.ID, &s.ScanID, &s.Role, &s.Username, &s.Cookies, &s.Headers, &s.Status, &s.CreatedAt, &s.LastUsedAt); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}
