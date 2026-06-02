package scanner

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/parth/lastresort/internal/storage"
)

// ScanHeaders checks for missing security headers in a given response.
func (as *ActiveScanner) ScanHeaders(ctx context.Context, scanID, urlStr string, respHeaders http.Header, respStatus int) error {
	securityHeaders := map[string]string{
		"Content-Security-Policy":   "Defends against Cross-Site Scripting (XSS) and data injection attacks by restricting resources.",
		"Strict-Transport-Security": "Forces connections over secure HTTPS, protecting against SSL stripping attacks.",
		"X-Frame-Options":           "Defends against clickjacking attacks by preventing the page from being framed.",
		"X-Content-Type-Options":    "Prevents browsers from MIME-sniffing the response away from the declared Content-Type.",
	}

	for header, desc := range securityHeaders {
		if respHeaders.Get(header) == "" {
			title := fmt.Sprintf("Missing Security Header: %s", header)
			description := fmt.Sprintf("The response does not include the %s header. %s", header, desc)
			severity := "LOW"
			if header == "Content-Security-Policy" || header == "Strict-Transport-Security" {
				severity = "MEDIUM"
			}

			flowID, flowErr := as.db.SaveFlow(ctx, scanID, "GET", urlStr, map[string][]string{}, nil, respHeaders, nil, respStatus)
			if flowErr != nil {
				return flowErr
			}

			_, err := as.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
				ScanID:            scanID,
				Title:             title,
				Description:       description,
				Severity:          severity,
				VulnerabilityType: "Security Misconfiguration",
				Endpoint:          urlStr,
				Payload:           "",
				ResponseStatus:    respStatus,
				Confidence:        0.7,
			}, storage.EvidenceInput{
				FlowID:          flowID,
				EvidenceType:    storage.EvidenceHeader,
				RequestExcerpt:  fmt.Sprintf("GET %s", urlStr),
				ResponseExcerpt: fmt.Sprintf("missing header: %s", header),
			})
			if err != nil {
				log.Printf("[Headers Scanner] [ERROR] Failed to save security header finding: %v", err)
			}
		}
	}

	return nil
}
