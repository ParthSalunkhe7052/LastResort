package orchestrator

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect"
	aiv1 "github.com/parth/lastresort/internal/gen/ai/v1"
	"github.com/parth/lastresort/internal/gen/ai/v1/aiv1connect"
	"github.com/parth/lastresort/internal/scanner"
	"github.com/parth/lastresort/internal/storage"
)

// VerificationEngine evaluates browser attack results and produces a VerificationResult.
type VerificationEngine struct {
	aiClient aiv1connect.AiServiceClient
}

// NewVerificationEngine constructs a VerificationEngine.
func NewVerificationEngine(aiClient aiv1connect.AiServiceClient) *VerificationEngine {
	return &VerificationEngine{aiClient: aiClient}
}


// VerifyXSS checks whether an XSS payload was executed.
func (ve *VerificationEngine) VerifyXSS(ctx context.Context, vulnType, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult {
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

	// Try AI-based verification first
	if ve.aiClient != nil {
		req := &aiv1.VerifyAttackResultRequest{
			Payload: payload,
			Response: &aiv1.ActionResult{
				Success:    true,
				CurrentUrl: endpoint,
				PageTitle:  "",
				Screenshot: screenshotB64,
				VisibleElements: &aiv1.BrowserContext{
					CurrentUrl: endpoint,
					PageSource: pageSource,
				},
			},
		}
		aiRes, err := ve.aiClient.VerifyAttackResult(ctx, connect.NewRequest(req))
		if err == nil && aiRes != nil && aiRes.Msg != nil {
			if aiRes.Msg.Confirmed {
				vr.Verified = true
				vr.Confidence = float64(aiRes.Msg.Confidence)
				vr.Method = storage.VerificationAIScored
				vr.EvidenceSummary = fmt.Sprintf("AI verification confirmed XSS: %s", aiRes.Msg.Reasoning)
				return vr
			}
		}
	}

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

	// Try AI-based verification first
	if ve.aiClient != nil {
		req := &aiv1.VerifyAttackResultRequest{
			Payload: payload,
			Response: &aiv1.ActionResult{
				Success:    true,
				CurrentUrl: endpoint,
				PageTitle:  "",
				Screenshot: screenshotB64,
				VisibleElements: &aiv1.BrowserContext{
					CurrentUrl: endpoint,
					PageSource: pageSource,
				},
			},
		}
		aiRes, err := ve.aiClient.VerifyAttackResult(ctx, connect.NewRequest(req))
		if err == nil && aiRes != nil && aiRes.Msg != nil {
			if aiRes.Msg.Confirmed {
				vr.Verified = true
				vr.Confidence = float64(aiRes.Msg.Confidence)
				vr.Method = storage.VerificationAIScored
				vr.EvidenceSummary = fmt.Sprintf("AI verification confirmed SQLi: %s", aiRes.Msg.Reasoning)
				return vr
			}
		}
	}

	// Try deterministic fallback if AI is unavailable or negative
	dvr := scanner.VerifySQLiDeterministic(endpoint, payload, pageSource, screenshotB64)
	if dvr.Verified {
		return dvr
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

	vr.Verified = false
	vr.EvidenceSummary = "CSRF verification: No clear success indicators found in response. Finding remains a hypothesis."
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
		vr.Verified = false
		vr.Confidence = 0.45
		vr.Method = storage.VerificationDOMMarker
		vr.EvidenceSummary = fmt.Sprintf("Generic verification: Payload reflection verified inside DOM, but no proof of exploit execution was found. Vulnerability: %s", vulnType)
		return vr
	}

	vr.EvidenceSummary = "Generic verification: no context reflection found."
	return vr
}
