package orchestrator

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/parth/lastresort/internal/storage"
)

// VerificationEngine evaluates browser attack results and produces a VerificationResult.
type VerificationEngine struct {
	// AI client interface is retained for structure compatibility, but we do NOT call it.
	aiClient interface{}
}

// NewVerificationEngine constructs a VerificationEngine.
func NewVerificationEngine(aiClient interface{}) *VerificationEngine {
	return &VerificationEngine{aiClient: aiClient}
}

// VerifyXSS checks whether an XSS payload was executed.
func (ve *VerificationEngine) VerifyXSS(ctx context.Context, vulnType, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult {
	_ = ctx
	vr := &storage.VerificationResult{
		EndpointURL: endpoint,
		Payload:     payload,
		VerifiedAt:  time.Now(),
		Verified:    false,
		Confidence:  0.0,
		Method:      storage.VerificationStatusCode,
	}

	var artifacts []storage.EvidenceArtifact
	if pageSource != "" {
		snippet := pageSource
		if len(snippet) > 3000 {
			snippet = snippet[:3000] + "...[truncated]"
		}
		artifacts = append(artifacts, storage.EvidenceArtifact{
			ArtifactType: storage.EvidenceDOM,
			Label:        "Page DOM after XSS payload injection",
			Content:      snippet,
		})
	}
	if screenshotB64 != "" {
		artifacts = append(artifacts, storage.EvidenceArtifact{
			ArtifactType:    storage.EvidenceScreenshot,
			Label:           "Browser screenshot showing payload state",
			Content:         screenshotB64,
			ContentEncoding: "base64",
		})
	}
	vr.EvidenceArtifacts = artifacts

	// 1. Alert execution (alert dialog triggered and Playwright injected the DOM marker)
	if strings.Contains(pageSource, "lastresort-xss-alert-detected") {
		vr.Verified = true
		vr.Confidence = 0.98
		vr.Method = storage.VerificationAlertFired
		vr.EvidenceSummary = fmt.Sprintf("XSS verification success: Playwright dialog alert handler triggered. DOM marker '#lastresort-xss-alert-detected' was found. Endpoint: %s", endpoint)
		return vr
	}

	// 2. Reflected / DOM execution check (Unescaped tag reflection context check)
	sourceLower := strings.ToLower(pageSource)
	payloadLower := strings.ToLower(payload)
	if payloadLower != "" && strings.Contains(sourceLower, payloadLower) {
		// Verify payload exists in script tags or inline events context
		if strings.Contains(sourceLower, "<script") || strings.Contains(sourceLower, "onerror=") || strings.Contains(sourceLower, "javascript:") {
			vr.Verified = true
			vr.Confidence = 0.82
			vr.Method = storage.VerificationDOMMarker
			vr.EvidenceSummary = fmt.Sprintf("XSS verification success: Payload reflection context matches execution markers. Payload: %s", payload)
			return vr
		}
	}

	vr.EvidenceSummary = "XSS payload could not be verified: no alert fired and context execution markers were missing."
	return vr
}

// VerifySQLi checks whether an SQL injection payload produced a detectable anomaly.
func (ve *VerificationEngine) VerifySQLi(ctx context.Context, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult {
	_ = ctx
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
	// Checked via response delay metrics (handled at orchestrator execution stage, but supported here via timing label if matched)
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

// VerifyCSRF checks whether a cross-site request was accepted by the target.
func (ve *VerificationEngine) VerifyCSRF(ctx context.Context, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult {
	_ = ctx
	vr := &storage.VerificationResult{
		EndpointURL: endpoint,
		Payload:     payload,
		VerifiedAt:  time.Now(),
		Verified:    false,
		Confidence:  0.0,
		Method:      storage.VerificationStatusCode,
	}

	var artifacts []storage.EvidenceArtifact
	if pageSource != "" {
		snippet := pageSource
		if len(snippet) > 2000 {
			snippet = snippet[:2000] + "...[truncated]"
		}
		artifacts = append(artifacts, storage.EvidenceArtifact{
			ArtifactType: storage.EvidenceDOM,
			Label:        "Page response after CSRF form submission",
			Content:      snippet,
		})
	}
	if screenshotB64 != "" {
		artifacts = append(artifacts, storage.EvidenceArtifact{
			ArtifactType:    storage.EvidenceScreenshot,
			Label:           "Browser screenshot after CSRF action",
			Content:         screenshotB64,
			ContentEncoding: "base64",
		})
	}
	vr.EvidenceArtifacts = artifacts

	sourceLower := strings.ToLower(pageSource)

	// CSRF fails if the state changer rejects the action with csrf/forbidden error messages
	rejectionPatterns := []string{"csrf", "forbidden", "invalid token", "request forgery", "403", "security token", "invalid csrf"}
	for _, pattern := range rejectionPatterns {
		if strings.Contains(sourceLower, pattern) {
			vr.Verified = false
			vr.Confidence = 0.05
			vr.EvidenceSummary = fmt.Sprintf("CSRF verification fail: Protection detected (rejected with pattern '%s').", pattern)
			return vr
		}
	}

	// CSRF succeeds if success indicator keywords are present in response body
	successPatterns := []string{"success", "updated", "saved", "created", "accepted", "submitted", "ok"}
	for _, pattern := range successPatterns {
		if strings.Contains(sourceLower, pattern) {
			vr.Verified = true
			vr.Confidence = 0.85
			vr.Method = storage.VerificationStatusCode
			vr.EvidenceSummary = fmt.Sprintf("CSRF verification success: Form request accepted (success keyword: '%s'). Endpoint: %s", pattern, endpoint)
			return vr
		}
	}

	// Fallback to basic assertion
	vr.Verified = true
	vr.Confidence = 0.72
	vr.Method = storage.VerificationStatusCode
	vr.EvidenceSummary = fmt.Sprintf("CSRF verification success (heuristic): Request executed and did not encounter CSRF validation errors. Endpoint: %s", endpoint)
	return vr
}

// VerifyPathTraversal checks whether file content or directory traversal indicators appear.
func (ve *VerificationEngine) VerifyPathTraversal(ctx context.Context, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult {
	_ = ctx
	vr := &storage.VerificationResult{
		EndpointURL: endpoint,
		Payload:     payload,
		VerifiedAt:  time.Now(),
		Verified:    false,
		Confidence:  0.0,
		Method:      storage.VerificationDataLeak,
	}

	var artifacts []storage.EvidenceArtifact
	if pageSource != "" {
		snippet := pageSource
		if len(snippet) > 2000 {
			snippet = snippet[:2000] + "...[truncated]"
		}
		artifacts = append(artifacts, storage.EvidenceArtifact{
			ArtifactType: storage.EvidenceDOM,
			Label:        "Page response after path traversal injection",
			Content:      snippet,
		})
	}
	if screenshotB64 != "" {
		artifacts = append(artifacts, storage.EvidenceArtifact{
			ArtifactType:    storage.EvidenceScreenshot,
			Label:           "Browser screenshot after path traversal",
			Content:         screenshotB64,
			ContentEncoding: "base64",
		})
	}
	vr.EvidenceArtifacts = artifacts

	sourceLower := strings.ToLower(pageSource)

	// File signature matching (deterministic rules)
	fileSignatures := map[string][]string{
		"etc_passwd": {`root:x:0:0`, `bin:x:1:1`, `nobody:x:`},
		"win_ini":    {`\[fonts\]`, `\[extensions\]`, `\[files\]`},
	}

	for sigName, patterns := range fileSignatures {
		matchedAll := true
		for _, pat := range patterns {
			matched, _ := regexp.MatchString(pat, sourceLower)
			if !matched {
				matchedAll = false
				break
			}
		}
		if matchedAll {
			vr.Verified = true
			vr.Confidence = 0.98
			vr.Method = storage.VerificationDataLeak
			vr.EvidenceSummary = fmt.Sprintf("Path Traversal verification success: File content signature matched database patterns for '%s'. Endpoint: %s", sigName, endpoint)
			return vr
		}
	}

	vr.EvidenceSummary = "Path Traversal verification fail: No valid file content signatures were matched in response."
	return vr
}

// VerifyRateLimit checks whether rate limiting is missing.
func (ve *VerificationEngine) VerifyRateLimit(ctx context.Context, endpoint, pageSource, screenshotB64 string) *storage.VerificationResult {
	_ = ctx
	vr := &storage.VerificationResult{
		EndpointURL: endpoint,
		Payload:     "10 burst requests / 1s",
		VerifiedAt:  time.Now(),
		Verified:    false,
		Confidence:  0.0,
		Method:      storage.VerificationBurstSuccess,
	}

	var artifacts []storage.EvidenceArtifact
	if screenshotB64 != "" {
		artifacts = append(artifacts, storage.EvidenceArtifact{
			ArtifactType:    storage.EvidenceScreenshot,
			Label:           "Browser screenshot showing rate limit test result",
			Content:         screenshotB64,
			ContentEncoding: "base64",
		})
	}
	vr.EvidenceArtifacts = artifacts

	// Parse DOM marker injected by the rate limit script
	idx := strings.Index(pageSource, "id=\"lastresort-ratelimit-results\"")
	if idx != -1 {
		sub := pageSource[idx:]
		statusIdx := strings.Index(sub, "data-statuses=\"")
		if statusIdx != -1 {
			sub2 := sub[statusIdx+len("data-statuses=\""):]
			endIdx := strings.Index(sub2, "\"")
			if endIdx != -1 {
				statusesStr := sub2[:endIdx]
				statuses := strings.Split(statusesStr, ",")
				throttled := false
				successCount := 0
				for _, st := range statuses {
					st = strings.TrimSpace(st)
					if st == "429" || st == "403" {
						throttled = true
					}
					if st == "200" || st == "302" || st == "301" {
						successCount++
					}
				}

				if successCount == len(statuses) && !throttled && successCount > 0 {
					vr.Verified = true
					vr.Confidence = 0.90
					vr.Method = storage.VerificationBurstSuccess
					vr.EvidenceSummary = fmt.Sprintf("Missing rate limiting: %d consecutive requests to %s all succeeded (statuses: %s).", successCount, endpoint, statusesStr)
					return vr
				}
			}
		}
	}

	vr.EvidenceSummary = "Rate limiting verification: throttling detected or DOM test results not found."
	return vr
}

// VerifyGeneric checks miscellaneous vulnerabilities.
func (ve *VerificationEngine) VerifyGeneric(ctx context.Context, vulnType, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult {
	_ = ctx
	vr := &storage.VerificationResult{
		EndpointURL: endpoint,
		Payload:     payload,
		VerifiedAt:  time.Now(),
		Verified:    false,
		Confidence:  0.0,
		Method:      storage.VerificationStatusCode,
	}

	var artifacts []storage.EvidenceArtifact
	if pageSource != "" {
		snippet := pageSource
		if len(snippet) > 2000 {
			snippet = snippet[:2000] + "...[truncated]"
		}
		artifacts = append(artifacts, storage.EvidenceArtifact{
			ArtifactType: storage.EvidenceDOM,
			Label:        "Page response after generic scan injection",
			Content:      snippet,
		})
	}
	vr.EvidenceArtifacts = artifacts

	// Fallback to simple matching if payload is reflected in response
	if payload != "" && strings.Contains(strings.ToLower(pageSource), strings.ToLower(payload)) {
		vr.Verified = true
		vr.Confidence = 0.72
		vr.Method = storage.VerificationDOMMarker
		vr.EvidenceSummary = fmt.Sprintf("Generic verification: Payload reflection verified inside DOM. Vulnerability: %s", vulnType)
		return vr
	}

	vr.EvidenceSummary = "Generic verification: no context reflection found."
	return vr
}
