package proxy

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/parth/lastresort/internal/storage"
)

// PassiveAnalyzer performs security scanning on HTTP transactions.
type PassiveAnalyzer struct {
	db *storage.DB
}

// NewPassiveAnalyzer creates a new PassiveAnalyzer instance.
func NewPassiveAnalyzer(db *storage.DB) *PassiveAnalyzer {
	return &PassiveAnalyzer{db: db}
}

// AnalyzeFlow runs passive checks on the given request and response.
func (pa *PassiveAnalyzer) AnalyzeFlow(ctx context.Context, scanID string, flowID int64, method, urlStr string, reqHeaders http.Header, respHeaders http.Header, respStatus int) {
	if scanID == "" {
		return
	}
	if flowID <= 0 {
		return
	}

	// 1. Check Missing Security Headers
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

			_, err := pa.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
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
				RequestExcerpt:  fmt.Sprintf("%s %s", method, urlStr),
				ResponseExcerpt: fmt.Sprintf("missing header: %s", header),
			})
			if err != nil {
				log.Printf("[Passive Analysis] [ERROR] Failed to save security header finding: %v", err)
			}
		}
	}

	// 2. Check Cookie flags (HttpOnly, Secure, SameSite)
	cookies := respHeaders.Values("Set-Cookie")
	for _, cookieStr := range cookies {
		parts := strings.Split(cookieStr, ";")
		if len(parts) == 0 {
			continue
		}
		
		nameValue := strings.TrimSpace(parts[0])
		cookieName := strings.Split(nameValue, "=")[0]

		// Skip tracking/third-party cookies; focus on session cookies
		cookieLower := strings.ToLower(cookieName)
		isSessionCookie := strings.Contains(cookieLower, "sess") || 
			strings.Contains(cookieLower, "token") || 
			strings.Contains(cookieLower, "jwt") || 
			strings.Contains(cookieLower, "auth") || 
			cookieLower == "id"

		if isSessionCookie {
			hasHttpOnly := false
			hasSecure := false
			hasSameSite := false

			for _, p := range parts[1:] {
				pTrim := strings.ToLower(strings.TrimSpace(p))
				if pTrim == "httponly" {
					hasHttpOnly = true
				}
				if pTrim == "secure" {
					hasSecure = true
				}
				if strings.HasPrefix(pTrim, "samesite") {
					hasSameSite = true
				}
			}

			if !hasHttpOnly {
				title := fmt.Sprintf("Session Cookie Missing HttpOnly Flag: %s", cookieName)
				description := fmt.Sprintf("The session/auth cookie '%s' is missing the HttpOnly flag. This allows client-side scripts to access the cookie, increasing vulnerability to session hijacking via XSS.", cookieName)
				_, err := pa.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
					ScanID:            scanID,
					Title:             title,
					Description:       description,
					Severity:          "MEDIUM",
					VulnerabilityType: "Insecure Session Cookie",
					Endpoint:          urlStr,
					Payload:           cookieName,
					ResponseStatus:    respStatus,
					Confidence:        0.8,
				}, storage.EvidenceInput{
					FlowID:          flowID,
					EvidenceType:    storage.EvidenceHeader,
					RequestExcerpt:  fmt.Sprintf("%s %s", method, urlStr),
					ResponseExcerpt: fmt.Sprintf("set-cookie: %s (missing HttpOnly)", cookieName),
				})
				if err != nil {
					log.Printf("[Passive Analysis] [ERROR] Failed to save cookie finding: %v", err)
				}
			}

			if !hasSecure {
				title := fmt.Sprintf("Session Cookie Missing Secure Flag: %s", cookieName)
				description := fmt.Sprintf("The session/auth cookie '%s' is missing the Secure flag. This allows the cookie to be transmitted over unencrypted HTTP, risking interception over cleartext networks.", cookieName)
				_, err := pa.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
					ScanID:            scanID,
					Title:             title,
					Description:       description,
					Severity:          "MEDIUM",
					VulnerabilityType: "Insecure Session Cookie",
					Endpoint:          urlStr,
					Payload:           cookieName,
					ResponseStatus:    respStatus,
					Confidence:        0.8,
				}, storage.EvidenceInput{
					FlowID:          flowID,
					EvidenceType:    storage.EvidenceHeader,
					RequestExcerpt:  fmt.Sprintf("%s %s", method, urlStr),
					ResponseExcerpt: fmt.Sprintf("set-cookie: %s (missing Secure)", cookieName),
				})
				if err != nil {
					log.Printf("[Passive Analysis] [ERROR] Failed to save cookie finding: %v", err)
				}
			}

			if !hasSameSite {
				title := fmt.Sprintf("Session Cookie Missing SameSite Flag: %s", cookieName)
				description := fmt.Sprintf("The session/auth cookie '%s' is missing the SameSite flag. This exposes the application to Cross-Site Request Forgery (CSRF) attacks.", cookieName)
				_, err := pa.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
					ScanID:            scanID,
					Title:             title,
					Description:       description,
					Severity:          "LOW",
					VulnerabilityType: "Insecure Session Cookie",
					Endpoint:          urlStr,
					Payload:           cookieName,
					ResponseStatus:    respStatus,
					Confidence:        0.6,
				}, storage.EvidenceInput{
					FlowID:          flowID,
					EvidenceType:    storage.EvidenceHeader,
					RequestExcerpt:  fmt.Sprintf("%s %s", method, urlStr),
					ResponseExcerpt: fmt.Sprintf("set-cookie: %s (missing SameSite)", cookieName),
				})
				if err != nil {
					log.Printf("[Passive Analysis] [ERROR] Failed to save cookie finding: %v", err)
				}
			}
		}
	}

	// 3. Insecure CORS Configuration
	allowOrigin := respHeaders.Get("Access-Control-Allow-Origin")
	allowCredentials := respHeaders.Get("Access-Control-Allow-Credentials")
	if allowOrigin == "*" && strings.ToLower(allowCredentials) == "true" {
		title := "Permissive CORS Configuration (Wildcard Origin with Credentials)"
		description := "The server configures CORS with a wildcard origin ('*') while allowing credentials. Standard browsers block this configuration, but it indicates misconfigured or overly permissive access policies."
		_, err := pa.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            scanID,
			Title:             title,
			Description:       description,
			Severity:          "LOW",
			VulnerabilityType: "CORS Misconfiguration",
			Endpoint:          urlStr,
			Payload:           "",
			ResponseStatus:    respStatus,
			Confidence:        0.65,
		}, storage.EvidenceInput{
			FlowID:          flowID,
			EvidenceType:    storage.EvidenceHeader,
			RequestExcerpt:  fmt.Sprintf("%s %s", method, urlStr),
			ResponseExcerpt: fmt.Sprintf("acao=%q acac=%q", allowOrigin, allowCredentials),
		})
		if err != nil {
			log.Printf("[Passive Analysis] [ERROR] Failed to save CORS finding: %v", err)
		}
	}
}
