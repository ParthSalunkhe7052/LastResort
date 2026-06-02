package storage

import (
	"context"
	"encoding/json"
	"fmt"
)

// HTTPFlow represents a saved HTTP transaction
type HTTPFlow struct {
	ID              int64  `json:"id"`
	ScanID          string `json:"scan_id"`
	Method          string `json:"method"`
	URL             string `json:"url"`
	RequestHeaders  string `json:"request_headers"`
	RequestBody     []byte `json:"request_body"`
	ResponseHeaders string `json:"response_headers"`
	ResponseBody    []byte `json:"response_body"`
	ResponseStatus  int    `json:"response_status"`
	CreatedAt       string `json:"created_at"`
}

// SaveFlow inserts a captured HTTP flow into the SQLite database.
func (db *DB) SaveFlow(ctx context.Context, scanID, method, urlStr string, reqHeaders map[string][]string, reqBody []byte, respHeaders map[string][]string, respBody []byte, respStatus int) (int64, error) {
	reqHeadersJSON, err := json.Marshal(reqHeaders)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal request headers: %w", err)
	}

	respHeadersJSON, err := json.Marshal(respHeaders)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal response headers: %w", err)
	}

	res, err := db.ExecContext(ctx,
		`INSERT INTO http_flows (scan_id, method, url, request_headers, request_body, response_headers, response_body, response_status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, method, urlStr, string(reqHeadersJSON), reqBody, string(respHeadersJSON), respBody, respStatus,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to insert http flow: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return id, nil
}
