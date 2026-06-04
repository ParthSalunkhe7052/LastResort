package storage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

type FormInput struct {
	ScanID   string
	URL      string
	Action   string
	Method   string
	Selector string
	Inputs   interface{} // JSON structure of inputs
}

type StoredForm struct {
	ID         string `json:"id"`
	ScanID     string `json:"scan_id"`
	URL        string `json:"url"`
	Action     string `json:"action"`
	Method     string `json:"method"`
	Selector   string `json:"selector"`
	InputsJSON string `json:"inputs_json"`
}

func (db *DB) CreateFormsTable() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS forms (
		id          TEXT PRIMARY KEY,
		scan_id     TEXT NOT NULL,
		url         TEXT NOT NULL,
		action      TEXT NOT NULL,
		method      TEXT NOT NULL DEFAULT 'GET',
		selector    TEXT,
		inputs_json TEXT,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		UNIQUE(scan_id, url, selector)
	)`)
	if err != nil {
		return fmt.Errorf("create forms table: %w", err)
	}
	return nil
}

func (db *DB) SaveForm(ctx context.Context, f FormInput) (string, error) {
	if f.ScanID == "" || f.URL == "" {
		return "", fmt.Errorf("ScanID and URL are required")
	}

	inputsJSON, err := json.Marshal(f.Inputs)
	if err != nil {
		return "", fmt.Errorf("marshal inputs: %w", err)
	}

	var existingID string
	err = db.QueryRowContext(ctx, "SELECT id FROM forms WHERE scan_id = ? AND url = ? AND selector = ?", f.ScanID, f.URL, f.Selector).Scan(&existingID)
	if err == nil {
		_, err = db.ExecContext(ctx,
			`UPDATE forms SET action = ?, method = ?, inputs_json = ? WHERE id = ?`,
			f.Action, f.Method, string(inputsJSON), existingID,
		)
		if err != nil {
			return "", fmt.Errorf("failed to update form: %w", err)
		}
		return existingID, nil
	}

	id := uuid.New().String()
	_, err = db.ExecContext(ctx,
		`INSERT INTO forms (id, scan_id, url, action, method, selector, inputs_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, f.ScanID, f.URL, f.Action, f.Method, f.Selector, string(inputsJSON),
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert form: %w", err)
	}
	return id, nil
}

func (db *DB) ListForms(ctx context.Context, scanID string) ([]*StoredForm, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, scan_id, url, action, method, COALESCE(selector, ''), COALESCE(inputs_json, '[]')
		 FROM forms WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query forms: %w", err)
	}
	defer rows.Close()

	var forms []*StoredForm
	for rows.Next() {
		var f StoredForm
		if err := rows.Scan(&f.ID, &f.ScanID, &f.URL, &f.Action, &f.Method, &f.Selector, &f.InputsJSON); err != nil {
			return nil, fmt.Errorf("failed to scan form row: %w", err)
		}
		forms = append(forms, &f)
	}
	return forms, nil
}
