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

// ScanXSS runs reflected XSS injection checks against all parameter points.
func (as *ActiveScanner) ScanXSS(ctx context.Context, scanID, method, urlStr string, body []byte, contentType string) error {
	points, err := ExtractInsertionPoints(method, urlStr, body, contentType)
	if err != nil {
		return err
	}

	payload := "<lr-xss-test>"

	for _, pt := range points {
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

		respContent := string(respBytes)
		if strings.Contains(respContent, payload) {
			title := fmt.Sprintf("Reflected XSS Vulnerability in Parameter: %s", pt.Name)
			description := fmt.Sprintf("The application reflects the user-supplied parameter '%s' unencoded in the response body. Payload used: %s", pt.Name, payload)
			severity := "HIGH"

			flowID, flowErr := as.db.SaveFlow(ctx, scanID, method, injectedURL, req.Header, injectedBody, resp.Header, respBytes, resp.StatusCode)
			if flowErr != nil {
				continue
			}
			respExcerpt := respContent
			if len(respExcerpt) > 2000 {
				respExcerpt = respExcerpt[:2000]
			}
			_, err = as.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
				ScanID:            scanID,
				Title:             title,
				Description:       description,
				Severity:          severity,
				VulnerabilityType: "Reflected XSS",
				Endpoint:          injectedURL,
				Payload:           payload,
				ResponseStatus:    resp.StatusCode,
				Confidence:        0.95,
			}, storage.EvidenceInput{
				FlowID:          flowID,
				EvidenceType:    storage.EvidenceBody,
				RequestExcerpt:  fmt.Sprintf("%s %s (injected %s)", method, injectedURL, pt.Name),
				ResponseExcerpt: respExcerpt,
			})
			if err != nil {
				log.Printf("[XSS Scanner] [ERROR] Failed to save finding: %v", err)
			}
		}
	}

	return nil
}
