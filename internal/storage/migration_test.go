package storage

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationCompatibility(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "lastresort_migration_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test_migration.db")

	// 1. Pre-create the database in an "old" state
	oldDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open old test database: %v", err)
	}

	// Create tables without the migrated columns
	_, err = oldDB.Exec(`
		CREATE TABLE scans (
			id TEXT PRIMARY KEY,
			target_url TEXT NOT NULL,
			status INTEGER DEFAULT 0,
			progress REAL DEFAULT 0.0,
			profile INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			started_at DATETIME,
			finished_at DATETIME
		);
		CREATE TABLE findings (
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
			is_false_positive INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		oldDB.Close()
		t.Fatalf("failed to setup old schema: %v", err)
	}
	oldDB.Close()

	// 2. Call InitDB which runs the migrations
	db, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed on old schema: %v", err)
	}
	defer db.Close()

	// 3. Verify columns exist by querying them
	var authCookies, scopePatterns sql.NullString
	err = db.QueryRowContext(t.Context(), "SELECT auth_cookies, scope_patterns FROM scans LIMIT 1").Scan(&authCookies, &scopePatterns)
	// QueryRow returns sql.ErrNoRows if empty, which is fine, as long as it doesn't return "no such column" error
	if err != nil && err != sql.ErrNoRows {
		t.Errorf("failed to query migrated columns on scans table: %v", err)
	}

	var category sql.NullString
	err = db.QueryRowContext(t.Context(), "SELECT category FROM findings LIMIT 1").Scan(&category)
	if err != nil && err != sql.ErrNoRows {
		t.Errorf("failed to query migrated category column on findings table: %v", err)
	}
}
