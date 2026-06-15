package storage

import (
	"database/sql"
	"fmt"
	"log"
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

	// Phase 6: attack journal table (idempotent).
	if err := storageDB.CreateJournalTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("journal tables migration failed: %w", err)
	}
	// Phase 2 (verification engine): attack verification table (idempotent).
	if err := storageDB.CreateVerificationTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("verification tables migration failed: %w", err)
	}
	// Phase 2 (attack replay): replay table (idempotent).
	if err := storageDB.CreateReplayTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("replay tables migration failed: %w", err)
	}
	// Phase 2 (runtime metrics): attack metrics table (idempotent).
	if err := storageDB.CreateMetricsTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("metrics tables migration failed: %w", err)
	}

	// P0.2 forms and attack attempts tables
	if err := storageDB.CreateFormsTable(); err != nil {
		db.Close()
		return nil, fmt.Errorf("forms tables migration failed: %w", err)
	}
	if err := storageDB.CreateAttacksTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("attack attempts tables migration failed: %w", err)
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
		        testing_mode INTEGER DEFAULT 1,
		        detected_technologies TEXT,
		        auth_model TEXT,
		        auth_cookies TEXT,
		        scope_patterns TEXT,
		        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		        started_at DATETIME,
		        finished_at DATETIME
		);`,
		`CREATE TABLE IF NOT EXISTS workflow_memory (
			id TEXT PRIMARY KEY,
			target_host TEXT NOT NULL,
			flow_type TEXT NOT NULL,
			actions_json TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
			verification_id TEXT,
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
		`CREATE TABLE IF NOT EXISTS finding_evidence (
			id TEXT PRIMARY KEY,
			finding_id TEXT NOT NULL,
			flow_id INTEGER,
			evidence_type TEXT NOT NULL,
			request_excerpt TEXT,
			response_excerpt TEXT,
			screenshot_path TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
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
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to create tables: %w", err)
		}
	}

	// Dynamic schema updates for existing databases (idempotent)
	_ = db.addColumnIfNotExists("scans", "detected_technologies", "TEXT")
	_ = db.addColumnIfNotExists("scans", "auth_model", "TEXT")
	_ = db.addColumnIfNotExists("scans", "auth_cookies", "TEXT")
	_ = db.addColumnIfNotExists("scans", "scope_patterns", "TEXT")
	_ = db.addColumnIfNotExists("scans", "testing_mode", "INTEGER DEFAULT 1")
	_ = db.addColumnIfNotExists("scans", "gemini_calls", "INTEGER DEFAULT 0")
	_ = db.addColumnIfNotExists("scans", "gemini_time_ms", "INTEGER DEFAULT 0")

	_ = db.addColumnIfNotExists("findings", "fingerprint", "TEXT")
	_ = db.addColumnIfNotExists("findings", "occurrence_count", "INTEGER DEFAULT 1")
	_ = db.addColumnIfNotExists("findings", "verification_id", "TEXT")
	_ = db.addColumnIfNotExists("findings", "category", "TEXT")

	_, _ = db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_scan_fingerprint ON findings (scan_id, fingerprint);")

	// Check if finding_evidence flow_id is NOT NULL
	var isNotNull bool
	rows, err := db.Query("PRAGMA table_info(finding_evidence)")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull int
			var dfltVal *string
			var pk int
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltVal, &pk); err == nil {
				if name == "flow_id" && notnull == 1 {
					isNotNull = true
				}
			}
		}
	}

	if isNotNull {
		log.Println("[DB] Migrating finding_evidence table to make flow_id nullable...")
		migrationQueries := []string{
			"PRAGMA foreign_keys=OFF;",
			"CREATE TABLE finding_evidence_new (id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, flow_id INTEGER, evidence_type TEXT NOT NULL, request_excerpt TEXT, response_excerpt TEXT, screenshot_path TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE);",
			"INSERT INTO finding_evidence_new SELECT id, finding_id, flow_id, evidence_type, request_excerpt, response_excerpt, screenshot_path, created_at FROM finding_evidence;",
			"DROP TABLE finding_evidence;",
			"ALTER TABLE finding_evidence_new RENAME TO finding_evidence;",
			"PRAGMA foreign_keys=ON;",
		}
		for _, q := range migrationQueries {
			if _, err := db.Exec(q); err != nil {
				log.Printf("[DB] [ERROR] Migration step failed: %s: %v", q, err)
			}
		}
	}

	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_evidence_finding_created ON finding_evidence (finding_id, created_at);")

	// Best-effort compatibility for older scan_modules schemas (idempotent)
	_ = db.addColumnIfNotExists("scan_modules", "module_name", "TEXT")
	_ = db.addColumnIfNotExists("scan_modules", "completed_at", "DATETIME")
	_ = db.addColumnIfNotExists("scan_modules", "error_message", "TEXT")

	return nil
}

// addColumnIfNotExists is a helper to safely add columns to an existing table.
func (db *DB) addColumnIfNotExists(tableName, columnName, columnDef string) error {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return fmt.Errorf("querying table info for %s: %w", tableName, err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltVal *string
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltVal, &pk); err != nil {
			return fmt.Errorf("scanning table info for %s: %w", tableName, err)
		}
		if name == columnName {
			return nil // Already exists
		}
	}

	query := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", tableName, columnName, columnDef)
	if _, err := db.Exec(query); err != nil {
		return fmt.Errorf("adding column %s to %s: %w", columnName, tableName, err)
	}
	return nil
}
