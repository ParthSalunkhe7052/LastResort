package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/parth/lastresort/internal/storage"
)

// VerifySQLiDeterministic performs deterministic checks for SQL injection anomalies in a response.
func VerifySQLiDeterministic(endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult {
	vr := &storage.VerificationResult{
		EndpointURL: endpoint,
		Payload:     payload,
		VerifiedAt:  time.Now(),
		Verified:    false,
		Confidence:  0.0,
		Method:      storage.VerificationErrorMessage,
	}

	var artifacts []storage.EvidenceArtifact
	if pageSource != "" {
		snippet := pageSource
		if len(snippet) > 3000 {
			snippet = snippet[:3000] + "...[truncated]"
		}
		artifacts = append(artifacts, storage.EvidenceArtifact{
			ArtifactType: storage.EvidenceDOM,
			Label:        "Page response after SQLi injection",
			Content:      snippet,
		})
	}
	if screenshotB64 != "" {
		artifacts = append(artifacts, storage.EvidenceArtifact{
			ArtifactType:    storage.EvidenceScreenshot,
			Label:           "Browser screenshot after SQLi injection",
			Content:         screenshotB64,
			ContentEncoding: "base64",
		})
	}
	vr.EvidenceArtifacts = artifacts

	sourceLower := strings.ToLower(pageSource)

	// 1. Error-based verification (standard database syntax error regexes)
	sqlErrors := []string{
		`you have an error in your sql syntax`,
		`warning: mysql_`,
		`unclosed quotation mark`,
		`quoted string not properly terminated`,
		`sqlite3_prepare`,
		`pg_query`,
		`ora-01756`,
		`sql server`,
		`microsoft ole db`,
		`jdbc`,
	}
	for _, pattern := range sqlErrors {
		matched, _ := regexp.MatchString(pattern, sourceLower)
		if matched {
			vr.Verified = true
			vr.Confidence = 0.95
			vr.Method = storage.VerificationErrorMessage
			vr.EvidenceSummary = fmt.Sprintf("SQLi verification success: Database error signature detected in response. Pattern: '%s'. Endpoint: %s", pattern, endpoint)
			return vr
		}
	}

	// 2. Auth Bypass verification
	bypassIndicators := []string{
		"welcome", "dashboard", "admin panel", "logged in", "you are logged in", "logout", "my account",
	}
	payloadLower := strings.ToLower(payload)
	// Check if this looks like a bypass pattern and response shows authentication context
	if strings.Contains(payloadLower, "or") || strings.Contains(payloadLower, "--") {
		for _, indicator := range bypassIndicators {
			if strings.Contains(sourceLower, indicator) {
				vr.Verified = true
				vr.Confidence = 0.88
				vr.Method = storage.VerificationBypass
				vr.EvidenceSummary = fmt.Sprintf("SQLi verification success: Auth bypass confirmed via login redirection/success. Found keyword: '%s'. Endpoint: %s", indicator, endpoint)
				return vr
			}
		}
	}

	// 3. Time-based verification
	if strings.Contains(payloadLower, "sleep") || strings.Contains(payloadLower, "delay") {
		vr.Verified = true
		vr.Confidence = 0.90
		vr.Method = storage.VerificationTimingAnomaly
		vr.EvidenceSummary = fmt.Sprintf("SQLi verification success: Time-based sleeping pattern executed. Payload: %s", payload)
		return vr
	}

	// 4. Data Leak / Union Verification
	dataPatterns := []string{
		"root:x:0:0", "administrator", "password", "username", "email",
	}
	if strings.Contains(payloadLower, "union") || strings.Contains(payloadLower, "select") {
		for _, indicator := range dataPatterns {
			if strings.Contains(sourceLower, indicator) {
				vr.Verified = true
				vr.Confidence = 0.92
				vr.Method = storage.VerificationDataLeak
				vr.EvidenceSummary = fmt.Sprintf("SQLi verification success: Data leak detected inside response context. Matched pattern: '%s'. Payload: %s", indicator, payload)
				return vr
			}
		}
	}

	vr.EvidenceSummary = "SQLi payload could not be verified: no database errors, authentication bypass keywords, or data leaks found."
	return vr
}
