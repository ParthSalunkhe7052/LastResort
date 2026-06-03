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
	securityHeaders := []struct {
		header string
		risk   string
		desc   string
	}{
		{
			header: "Content-Security-Policy",
			risk:   "Future XSS vulnerabilities may be easier to exploit due to lack of resource restriction.",
			desc:   "The response did not contain a Content-Security-Policy header, which is used to define which dynamic resources are allowed to load.",
		},
		{
			header: "Strict-Transport-Security",
			risk:   "The application may be vulnerable to SSL stripping attacks or insecure connection downgrades.",
			desc:   "The response did not contain a Strict-Transport-Security header, which forces the browser to use HTTPS for all future requests.",
		},
		{
			header: "X-Frame-Options",
			risk:   "The application could be embedded in an iframe, potentially leading to clickjacking attacks.",
			desc:   "The response did not contain an X-Frame-Options header, which prevents the page from being framed by other sites.",
		},
		{
			header: "X-Content-Type-Options",
			risk:   "Browsers might try to guess the content type (MIME-sniffing), which can lead to security issues with user-uploaded files.",
			desc:   "The response did not contain an X-Content-Type-Options: nosniff header.",
		},
	}

	for _, sh := range securityHeaders {
		if respHeaders.Get(sh.header) == "" {
			title := fmt.Sprintf("Missing Security Header: %s", sh.header)
			description := fmt.Sprintf("%s\n\nPotential Risk: %s\n\nConfidence: Observed directly in HTTP response. No attack occurred.", sh.desc, sh.risk)
			severity := "LOW"
			if sh.header == "Content-Security-Policy" || sh.header == "Strict-Transport-Security" {
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
				Confidence:        0.9,
				Category:          "OBSERVATION",
			}, storage.EvidenceInput{
				FlowID:          flowID,
				EvidenceType:    storage.EvidenceHeader,
				RequestExcerpt:  fmt.Sprintf("GET %s", urlStr),
				ResponseExcerpt: fmt.Sprintf("missing header: %s", sh.header),
			})
			if err != nil {
				log.Printf("[Headers Scanner] [ERROR] Failed to save security header finding: %v", err)
			}
		}
	}

	return nil
}
