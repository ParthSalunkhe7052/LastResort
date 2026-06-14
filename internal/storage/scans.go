package storage

import (
	"context"
	"encoding/json"
	"fmt"
)

// GetScopePatterns retrieves the list of scope patterns for a given scan.
func (db *DB) GetScopePatterns(ctx context.Context, scanID string) ([]string, error) {
	var patternsJSON string
	err := db.QueryRowContext(ctx, "SELECT COALESCE(scope_patterns, '[]') FROM scans WHERE id = ?", scanID).Scan(&patternsJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to get scope patterns: %w", err)
	}

	var patterns []string
	if err := json.Unmarshal([]byte(patternsJSON), &patterns); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scope patterns: %w", err)
	}

	return patterns, nil
}
