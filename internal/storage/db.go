package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// DB represents the database storage engine.
type DB struct {
	*sql.DB
}

// InitDB initializes the SQLite database at the specified path and creates tables.
func InitDB(dbPath string) (*DB, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	db.SetMaxOpenConns(1)

	// Performance optimization pragmas
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA synchronous=NORMAL;",
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to execute pragma %s: %w", pragma, err)
		}
	}

	storageDB := &DB{db}
	if err := storageDB.createTables(); err != nil {
		db.Close()
		return nil, err
	}
	// Migration for category column
	_, _ = storageDB.Exec("ALTER TABLE findings ADD COLUMN category TEXT")
	// Phase 3: workflow intelligence tables (idempotent).
	if err := storageDB.CreateWorkflowTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("workflow tables migration failed: %w", err)
	}
	// Phase 5: attack goals table (idempotent).
	if err := storageDB.CreateGoalTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("goals table migration failed: %w", err)
	}

	return storageDB, nil
}

func (db *DB) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS projects (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			target_url TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			target_url TEXT NOT NULL,
			status INTEGER DEFAULT 0,
			progress REAL DEFAULT 0.0,
			profile INTEGER DEFAULT 0,
			detected_technologies TEXT,
			auth_model TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			started_at DATETIME,
			finished_at DATETIME
		);`,
		`CREATE TABLE IF NOT EXISTS http_flows (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT NOT NULL,
			method TEXT NOT NULL,
			url TEXT NOT NULL,
			request_headers TEXT,
			request_body BLOB,
			response_headers TEXT,
			response_body BLOB,
			response_status INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			scan_id TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			severity TEXT NOT NULL,
			vulnerability_type TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			payload TEXT,
			response_status INTEGER,
			confidence REAL,
			category TEXT,
			is_false_positive INTEGER DEFAULT 0,
			fingerprint TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS scan_modules (
			scan_id TEXT NOT NULL,
			module_name TEXT NOT NULL,
			status TEXT NOT NULL,
			started_at DATETIME,
			completed_at DATETIME,
			error_message TEXT,
			PRIMARY KEY (scan_id, module_name),
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS endpoints (
			id TEXT PRIMARY KEY,
			scan_id TEXT NOT NULL,
			method TEXT NOT NULL,
			url TEXT NOT NULL,
			source TEXT NOT NULL,
			status_code INTEGER,
			content_type TEXT,
			first_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			fingerprint TEXT NOT NULL,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
			UNIQUE(scan_id, fingerprint)
		);`,
		`CREATE TABLE IF NOT EXISTS hypotheses (
			id TEXT PRIMARY KEY,
			scan_id TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			confidence REAL,
			source TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS finding_evidence (
			id TEXT PRIMARY KEY,
			finding_id TEXT NOT NULL,
			flow_id INTEGER NOT NULL,
			evidence_type TEXT NOT NULL,
			request_excerpt TEXT,
			response_excerpt TEXT,
			screenshot_path TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
			FOREIGN KEY (flow_id) REFERENCES http_flows(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS reports (
			id TEXT PRIMARY KEY,
			scan_id TEXT NOT NULL,
			format TEXT NOT NULL,
			path TEXT NOT NULL,
			title TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		);`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to create tables: %w", err)
		}
	}

	// Dynamic schema updates for existing databases
	_, _ = db.Exec("ALTER TABLE scans ADD COLUMN detected_technologies TEXT;")
	_, _ = db.Exec("ALTER TABLE scans ADD COLUMN auth_model TEXT;")
	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN fingerprint TEXT;")
	_, _ = db.Exec("ALTER TABLE scans ADD COLUMN gemini_calls INTEGER DEFAULT 0;")
	_, _ = db.Exec("ALTER TABLE scans ADD COLUMN gemini_time_ms INTEGER DEFAULT 0;")
	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN occurrence_count INTEGER DEFAULT 1;")
	_, _ = db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_scan_fingerprint ON findings (scan_id, fingerprint);")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_hypotheses_scan_created ON hypotheses (scan_id, created_at);")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_evidence_finding_created ON finding_evidence (finding_id, created_at);")

	// Best-effort compatibility for older scan_modules schemas.
	_, _ = db.Exec("ALTER TABLE scan_modules ADD COLUMN module_name TEXT;")
	_, _ = db.Exec("ALTER TABLE scan_modules ADD COLUMN completed_at DATETIME;")
	_, _ = db.Exec("ALTER TABLE scan_modules ADD COLUMN error_message TEXT;")
	_, _ = db.Exec("ALTER TABLE scan_modules ADD COLUMN module TEXT;")
	_, _ = db.Exec("ALTER TABLE scan_modules ADD COLUMN finished_at DATETIME;")
	_, _ = db.Exec("ALTER TABLE scan_modules ADD COLUMN error TEXT;")
	_, _ = db.Exec("ALTER TABLE hypotheses ADD COLUMN source TEXT;")
	_, _ = db.Exec("ALTER TABLE hypotheses ADD COLUMN status TEXT;")

	return nil
}
