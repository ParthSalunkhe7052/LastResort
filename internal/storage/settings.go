package storage

import (
	"context"
	"database/sql"
)

// GetSetting retrieves a setting by key. Returns empty string if not found.
func (db *DB) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

// SaveSetting saves a key-value setting.
func (db *DB) SaveSetting(ctx context.Context, key, value string) error {
	_, err := db.ExecContext(ctx,
		"INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
		key, value, value,
	)
	return err
}

// GetAllSettings retrieves all settings as a map.
func (db *DB) GetAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		settings[key] = value
	}
	return settings, nil
}
