package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Endpoint represents a route/endpoint discovered during active or passive stages.
type Endpoint struct {
	ID          string `json:"id"`
	ScanID      string `json:"scan_id"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Source      string `json:"source"`
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type"`
	FirstSeenAt string `json:"first_seen_at"`
	LastSeenAt  string `json:"last_seen_at"`
}

// GenerateEndpointFingerprint calculates a unique hash for an endpoint method + url combination.
func GenerateEndpointFingerprint(method, urlStr string) string {
	normMethod := strings.TrimSpace(strings.ToUpper(method))
	normURL := strings.TrimSpace(strings.ToLower(urlStr))
	input := normMethod + "|" + normURL
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// SaveEndpoint inserts a new discovered endpoint or updates an existing one if a fingerprint collision occurs.
func (db *DB) SaveEndpoint(ctx context.Context, scanID, method, urlStr, source string, statusCode int, contentType string) (string, error) {
	fp := GenerateEndpointFingerprint(method, urlStr)

	// Check if already exists
	var existingID string
	err := db.QueryRowContext(ctx, "SELECT id FROM endpoints WHERE scan_id = ? AND fingerprint = ?", scanID, fp).Scan(&existingID)
	if err == nil {
		// Update existing endpoint
		_, err = db.ExecContext(ctx,
			`UPDATE endpoints SET
				last_seen_at = CURRENT_TIMESTAMP,
				status_code = ?,
				content_type = ?
			 WHERE id = ?`,
			statusCode, contentType, existingID,
		)
		if err != nil {
			return "", fmt.Errorf("failed to update endpoint: %w", err)
		}
		return existingID, nil
	}

	// Insert new endpoint
	endpointID := uuid.New().String()
	_, err = db.ExecContext(ctx,
		`INSERT INTO endpoints (id, scan_id, method, url, source, status_code, content_type, first_seen_at, last_seen_at, fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		endpointID, scanID, method, urlStr, source, statusCode, contentType, time.Now(), time.Now(), fp,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert endpoint: %w", err)
	}

	return endpointID, nil
}

// ListEndpoints returns all discovered endpoints for a given scan, ordered by source, then url.
func (db *DB) ListEndpoints(ctx context.Context, scanID string) ([]*Endpoint, error) {
	var rows *sql.Rows
	var err error

	if scanID != "" {
		rows, err = db.QueryContext(ctx,
			`SELECT id, scan_id, method, url, source, status_code, content_type, first_seen_at, last_seen_at
			 FROM endpoints WHERE scan_id = ? ORDER BY source, url`, scanID)
	} else {
		rows, err = db.QueryContext(ctx,
			`SELECT id, scan_id, method, url, source, status_code, content_type, first_seen_at, last_seen_at
			 FROM endpoints ORDER BY source, url`)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query endpoints: %w", err)
	}
	defer rows.Close()

	var endpoints []*Endpoint
	for rows.Next() {
		var ep Endpoint
		var statusCode sql.NullInt64
		var contentType sql.NullString
		var firstSeen, lastSeen time.Time

		err := rows.Scan(&ep.ID, &ep.ScanID, &ep.Method, &ep.URL, &ep.Source, &statusCode, &contentType, &firstSeen, &lastSeen)
		if err != nil {
			return nil, fmt.Errorf("failed to scan endpoint row: %w", err)
		}

		ep.StatusCode = int(statusCode.Int64)
		ep.ContentType = contentType.String
		ep.FirstSeenAt = firstSeen.Format(time.RFC3339)
		ep.LastSeenAt = lastSeen.Format(time.RFC3339)

		endpoints = append(endpoints, &ep)
	}

	return endpoints, nil
}
