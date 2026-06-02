package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type CSRFHeuristicResult struct {
	Suspected bool
	Title     string
	Reason    string
}

// DetectCSRFHeuristic flags potential CSRF risk based on missing token indicators.
// It does NOT create findings (heuristic-only).
func DetectCSRFHeuristic(method, urlStr string, reqHeaders http.Header, body []byte, contentType string) (*CSRFHeuristicResult, error) {
	methodUpper := strings.ToUpper(method)
	if methodUpper != "POST" && methodUpper != "PUT" && methodUpper != "PATCH" && methodUpper != "DELETE" {
		return &CSRFHeuristicResult{Suspected: false}, nil
	}

	// 1. Check for anti-CSRF headers (case-insensitive)
	hasAntiCSRFHeader := false
	csrfHeaders := []string{"csrf", "xsrf", "csrf-token", "xsrf-token", "x-csrf-token", "x-xsrf-token"}
	for key := range reqHeaders {
		kLower := strings.ToLower(key)
		for _, ch := range csrfHeaders {
			if kLower == ch {
				hasAntiCSRFHeader = true
				break
			}
		}
	}

	if hasAntiCSRFHeader {
		return &CSRFHeuristicResult{Suspected: false}, nil
	}

	// 2. Check body parameters for anti-csrf tokens
	points, err := ExtractInsertionPoints(method, urlStr, body, contentType)
	if err != nil {
		return nil, err
	}

	hasCSRFParam := false
	csrfParams := []string{"csrf", "xsrf", "token", "csrftoken", "xsrftoken", "authenticity_token"}
	for _, pt := range points {
		pLower := strings.ToLower(pt.Name)
		for _, cp := range csrfParams {
			if strings.Contains(pLower, cp) {
				hasCSRFParam = true
				break
			}
		}
	}

	if !hasCSRFParam {
		title := fmt.Sprintf("Possible Missing Anti-CSRF Protection on State-Changing Action: %s", methodUpper)
		reason := fmt.Sprintf("State-changing request to %s does not contain any anti-CSRF header or token-like parameter. This is heuristic only; exploitability not verified.", urlStr)
		return &CSRFHeuristicResult{Suspected: true, Title: title, Reason: reason}, nil
	}

	return &CSRFHeuristicResult{Suspected: false}, nil
}

// ScanCSRF is retained for compatibility but does not create findings.
func (as *ActiveScanner) ScanCSRF(ctx context.Context, scanID, method, urlStr string, reqHeaders http.Header, body []byte, contentType string) error {
	_ = scanID
	_, err := DetectCSRFHeuristic(method, urlStr, reqHeaders, body, contentType)
	return err
}
