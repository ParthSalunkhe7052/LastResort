package storage

import (
	"context"
	"fmt"
)

// SaveAuthCookies persists JSON-encoded session cookies for a scan.
func (db *DB) SaveAuthCookies(ctx context.Context, scanID, cookiesJSON string) error {
	_, err := db.ExecContext(ctx, "UPDATE scans SET auth_cookies = ? WHERE id = ?", cookiesJSON, scanID)
	if err != nil {
		return fmt.Errorf("failed to save auth cookies: %w", err)
	}
	return nil
}

// GetAuthCookies retrieves JSON-encoded session cookies for a scan.
func (db *DB) GetAuthCookies(ctx context.Context, scanID string) (string, error) {
	var cookies string
	err := db.QueryRowContext(ctx, "SELECT COALESCE(auth_cookies, '') FROM scans WHERE id = ?", scanID).Scan(&cookies)
	if err != nil {
		return "", fmt.Errorf("failed to get auth cookies: %w", err)
	}
	return cookies, nil
}
