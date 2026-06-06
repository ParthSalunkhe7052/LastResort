package scanner

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/parth/lastresort/internal/storage"
)

// ScanCORS tests if the endpoint reflects arbitrary origins in CORS response headers.
func (as *ActiveScanner) ScanCORS(ctx context.Context, scanID, urlStr string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return err
	}

	testOrigin := "http://evil-attacker.com"
	req.Header.Set("Origin", testOrigin)

	resp, err := as.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")

	if (allowOrigin == testOrigin || allowOrigin == "*") && strings.ToLower(allowCredentials) == "true" {
		title := "Permissive CORS Configuration (Reflected or Wildcard Origin with Credentials)"
		description := fmt.Sprintf("The server echoes arbitrary Origin headers ('%s') or wildcard ('*') in Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials to true. This allows unauthorized cross-site requests to read response content.", allowOrigin)
		severity := "HIGH"

		_, err = as.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            scanID,
			Title:             title,
			Description:       description,
			Severity:          severity,
			VulnerabilityType: "CORS Misconfiguration",
			Endpoint:          urlStr,
			Payload:           testOrigin,
			ResponseStatus:    resp.StatusCode,
			Confidence:        0.9,
		}, storage.EvidenceInput{
			FlowID:          0,
			EvidenceType:    storage.EvidenceHeader,
			RequestExcerpt:  fmt.Sprintf("GET %s\nOrigin: %s", urlStr, testOrigin),
			ResponseExcerpt: fmt.Sprintf("Access-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s", allowOrigin, allowCredentials),
		})
		if err != nil {
			log.Printf("[CORS Scanner] [ERROR] Failed to save finding: %v", err)
		}
	}

	return nil
}
