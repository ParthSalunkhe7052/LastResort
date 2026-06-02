package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/parth/lastresort/internal/storage"
)

// ScanSQLi runs basic SQL injection checks against parameter insertion points.
func (as *ActiveScanner) ScanSQLi(ctx context.Context, scanID, method, urlStr string, body []byte, contentType string) error {
	points, err := ExtractInsertionPoints(method, urlStr, body, contentType)
	if err != nil {
		return err
	}

	payloads := []string{"'", "\"", "')", "1 OR 1=1"}
	errorMarkers := []string{
		"sql syntax",
		"sqlite/jdbc",
		"sqlite3",
		"sqlite",
		"postgresql",
		"mysql",
		"ora-",
		"odbc",
		"syntax error",
		"db error",
	}

	for _, pt := range points {
		for _, payload := range payloads {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			injectedURL, injectedBody := BuildInjectedRequest(method, urlStr, body, contentType, pt, payload)

			req, err := http.NewRequestWithContext(ctx, method, injectedURL, bytes.NewReader(injectedBody))
			if err != nil {
				continue
			}
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}

			resp, err := as.client.Do(req)
			if err != nil {
				continue
			}
			respBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
			resp.Body.Close()
			if readErr != nil {
				continue
			}

			respContent := strings.ToLower(string(respBytes))
			matchedMarker := ""
			for _, marker := range errorMarkers {
				if strings.Contains(respContent, marker) {
					matchedMarker = marker
					break
				}
			}

			if matchedMarker != "" {
				title := fmt.Sprintf("Potential SQL Injection in Parameter: %s", pt.Name)
				description := fmt.Sprintf("The application endpoint returned a database error indicator ('%s') when injecting SQL payload '%s' in parameter '%s'.", matchedMarker, payload, pt.Name)
				severity := "HIGH"

				flowID, flowErr := as.db.SaveFlow(ctx, scanID, method, injectedURL, req.Header, injectedBody, resp.Header, respBytes, resp.StatusCode)
				if flowErr != nil {
					break
				}

				respExcerpt := string(respBytes)
				if len(respExcerpt) > 2000 {
					respExcerpt = respExcerpt[:2000]
				}
				_, err = as.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
					ScanID:            scanID,
					Title:             title,
					Description:       description,
					Severity:          severity,
					VulnerabilityType: "SQL Injection",
					Endpoint:          injectedURL,
					Payload:           payload,
					ResponseStatus:    resp.StatusCode,
					Confidence:        0.9,
				}, storage.EvidenceInput{
					FlowID:          flowID,
					EvidenceType:    storage.EvidenceBody,
					RequestExcerpt:  fmt.Sprintf("%s %s (injected %s)", method, injectedURL, pt.Name),
					ResponseExcerpt: respExcerpt,
				})
				if err != nil {
					log.Printf("[SQLi Scanner] [ERROR] Failed to save finding: %v", err)
				}
				break
			}
		}
	}

	return nil
}
