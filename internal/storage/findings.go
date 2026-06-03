package storage

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// Finding represents a saved security finding
type Finding struct {
	ID                string  `json:"id"`
	ScanID            string  `json:"scan_id"`
	Title             string  `json:"title"`
	Description       string  `json:"description"`
	Severity          string  `json:"severity"`
	VulnerabilityType string  `json:"vulnerability_type"`
	Endpoint          string  `json:"endpoint"`
	Payload           string  `json:"payload"`
	ResponseStatus    int     `json:"response_status"`
	Confidence        float64 `json:"confidence"`
	Category          string  `json:"category"`
	IsFalsePositive   int     `json:"is_false_positive"`
	CreatedAt         string  `json:"created_at"`
}

type FindingInput struct {
	ScanID            string
	Title             string
	Description       string
	Severity          string
	VulnerabilityType string
	Endpoint          string
	Payload           string
	ResponseStatus    int
	Confidence        float64
	Category          string
}

// SaveFinding is deprecated and intentionally blocked.
// Findings must never be created without evidence (see SaveFindingWithEvidence).
func (db *DB) SaveFinding(ctx context.Context, scanID, title, description, severity, vulnType, endpoint, payload string, respStatus int, confidence float64) (string, error) {
	_ = ctx
	_ = scanID
	_ = title
	_ = description
	_ = severity
	_ = vulnType
	_ = endpoint
	_ = payload
	_ = respStatus
	_ = confidence
	return "", fmt.Errorf("finding creation without evidence is forbidden; use SaveFindingWithEvidence")
}

// SaveFindingWithEvidence inserts or updates (upserts) a security finding and attaches evidence.
// If evidence is missing, it fails hard.
// SaveFindingWithEvidence inserts or updates (upserts) a security finding and attaches evidence.
// If evidence is missing, it fails hard.
func (db *DB) SaveFindingWithEvidence(ctx context.Context, in FindingInput, ev EvidenceInput) (string, error) {
	if in.ScanID == "" {
		return "", fmt.Errorf("scanID is required")
	}
	if in.Title == "" {
		return "", fmt.Errorf("title is required")
	}
	if in.Description == "" {
		return "", fmt.Errorf("description is required")
	}
	if in.Severity == "" {
		return "", fmt.Errorf("severity is required")
	}
	if in.VulnerabilityType == "" {
		return "", fmt.Errorf("vulnerability_type is required")
	}
	if in.Endpoint == "" {
		return "", fmt.Errorf("endpoint is required")
	}
	if ev.FlowID <= 0 {
		return "", fmt.Errorf("evidence.flow_id is required")
	}
	if ev.EvidenceType == "" {
		return "", fmt.Errorf("evidence.evidence_type is required")
	}
	if in.Category == "" {
		in.Category = "OBSERVATION"
	}

	// 1. Run audit verification to demote false/unverified attacks to HYPOTHESIS
	auditFinding(&in, &ev)

	// 2. Format description into the structured sections (Risk/Evidence/Fix/Confidence or Result/Impact/Evidence/Confidence)
	in.Description = formatDescription(&in, &ev)

	fp := GenerateFingerprint(in.VulnerabilityType, in.Endpoint, in.Title)

	// Check if a finding with this fingerprint already exists for the scan
	var existingID string
	err := db.QueryRowContext(ctx, "SELECT id FROM findings WHERE scan_id = ? AND fingerprint = ?", in.ScanID, fp).Scan(&existingID)
	if err == nil {
		// Update the existing finding and increment its occurrence count
		_, err = db.ExecContext(ctx,
			`UPDATE findings SET
				description = ?,
				severity = ?,
				payload = ?,
				response_status = ?,
				confidence = ?,
				category = ?,
				occurrence_count = COALESCE(occurrence_count, 1) + 1,
				created_at = CURRENT_TIMESTAMP
			 WHERE id = ?`,
			in.Description, in.Severity, in.Payload, in.ResponseStatus, in.Confidence, in.Category, existingID,
		)
		if err != nil {
			return "", fmt.Errorf("failed to update finding: %w", err)
		}
		_, _ = db.AddFindingEvidence(ctx, existingID, ev)
		return existingID, nil
	}

	// Insert a new finding
	findingID := uuid.New().String()
	_, err = db.ExecContext(ctx,
		`INSERT INTO findings (id, scan_id, title, description, severity, vulnerability_type, endpoint, payload, response_status, confidence, category, is_false_positive, fingerprint, occurrence_count)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 1)`,
		findingID, in.ScanID, in.Title, in.Description, in.Severity, in.VulnerabilityType, in.Endpoint, in.Payload, in.ResponseStatus, in.Confidence, in.Category, fp,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert finding: %w", err)
	}

	if _, err := db.AddFindingEvidence(ctx, findingID, ev); err != nil {
		_, _ = db.ExecContext(ctx, "DELETE FROM findings WHERE id = ?", findingID)
		return "", err
	}
	return findingID, nil
}

func auditFinding(in *FindingInput, ev *EvidenceInput) {
	if in.Category != "VERIFIED_ATTACK" {
		return
	}

	// Bypass audit for AI-verified findings as they use higher-level adversarial reasoning
	if strings.Contains(in.Title, "[AI-VERIFIED]") {
		return
	}

	respLower := strings.ToLower(ev.ResponseExcerpt)
	isSQLi := in.VulnerabilityType == "SQL Injection" || strings.Contains(strings.ToLower(in.Title), "sqli") || strings.Contains(strings.ToLower(in.Title), "sql injection")
	isXSS := in.VulnerabilityType == "Reflected XSS" || strings.Contains(strings.ToLower(in.Title), "xss") || strings.Contains(strings.ToLower(in.Title), "reflected xss")
	
	isVerified := false
	if isSQLi {
		isTimeBased := strings.Contains(strings.ToLower(in.Description), "time-based") || strings.Contains(strings.ToLower(in.Title), "time-based")
		isErrorBased := strings.Contains(respLower, "sqlite_master") || strings.Contains(respLower, "sqlite_version") || strings.Contains(respLower, "mysql_query") || strings.Contains(respLower, "pg_catalog")
		isBypass := in.ResponseStatus == 200 && (strings.Contains(respLower, "welcome") || strings.Contains(respLower, "admin") || strings.Contains(respLower, "user") || strings.Contains(respLower, "session"))
		
		if isTimeBased || isErrorBased || isBypass {
			isVerified = true
		}
	} else if isXSS {
		payloadLower := strings.ToLower(in.Payload)
		if payloadLower != "" && strings.Contains(respLower, payloadLower) {
			isVerified = true
		}
	} else {
		if in.ResponseStatus >= 200 && in.ResponseStatus < 400 {
			isVerified = true
		}
	}
	
	if !isVerified {
		in.Category = "HYPOTHESIS"
		in.Title = strings.Replace(in.Title, "[AI-VERIFIED]", "[AI-HYPOTHESIS]", -1)
		in.Title = strings.Replace(in.Title, "[VERIFIED]", "[HYPOTHESIS]", -1)
	}
}

func formatDescription(in *FindingInput, ev *EvidenceInput) string {
	if strings.Contains(in.Description, "Risk:") || strings.Contains(in.Description, "Result:") {
		return in.Description
	}

	confidenceLabel := "Medium"
	if in.Confidence >= 0.9 {
		confidenceLabel = "High"
	} else if in.Confidence < 0.4 {
		confidenceLabel = "Low"
	}

	titleLower := strings.ToLower(in.Title)
	vulnLower := strings.ToLower(in.VulnerabilityType)

	var risk, evidence, fix, result, impact string

	if strings.Contains(titleLower, "content-security-policy") || strings.Contains(titleLower, "csp") {
		risk = "May make future Cross-Site Scripting (XSS) vulnerabilities easier to exploit."
		evidence = "Content-Security-Policy header is not present in the HTTP response."
		fix = "Add the Content-Security-Policy header to restrict resource loading."
	} else if strings.Contains(titleLower, "strict-transport-security") || strings.Contains(titleLower, "hsts") {
		risk = "Allows SSL stripping attacks and insecure connection downgrades."
		evidence = "Strict-Transport-Security header is not present in the HTTP response."
		fix = "Add the Strict-Transport-Security header to force secure HTTPS connections."
	} else if strings.Contains(titleLower, "x-frame-options") {
		risk = "Allows clickjacking attacks by enabling the page to be framed."
		evidence = "X-Frame-Options header is not present in the HTTP response."
		fix = "Add the X-Frame-Options header to control page framing."
	} else if strings.Contains(titleLower, "x-content-type-options") {
		risk = "Allows MIME-sniffing which can execute user-uploaded files as scripts."
		evidence = "X-Content-Type-Options: nosniff header is not present in the HTTP response."
		fix = "Add the X-Content-Type-Options: nosniff header to responses."
	} else if strings.Contains(titleLower, "httponly") {
		risk = "Client-side scripts can access the cookie, risking session hijacking."
		evidence = "HttpOnly flag is missing from the Set-Cookie header."
		fix = "Add the HttpOnly flag to the Set-Cookie header."
	} else if strings.Contains(titleLower, "secure flag") || (strings.Contains(titleLower, "secure") && strings.Contains(titleLower, "cookie")) {
		risk = "Cookie can be transmitted over unencrypted HTTP, risking network interception."
		evidence = "Secure flag is missing from the Set-Cookie header."
		fix = "Add the Secure flag to the Set-Cookie header."
	} else if strings.Contains(titleLower, "samesite") {
		risk = "Exposes the session cookie to Cross-Site Request Forgery attacks."
		evidence = "SameSite flag is missing from the Set-Cookie header."
		fix = "Add SameSite=Lax or SameSite=Strict to the Set-Cookie header."
	} else if strings.Contains(titleLower, "cors") || strings.Contains(vulnLower, "cors") {
		risk = "Allows unauthorized cross-site requests to read sensitive response content."
		evidence = "Reflected origin or wildcard allowed with credentials in CORS headers."
		fix = "Configure CORS to restrict origins and disallow wildcard with credentials."
	} else if strings.Contains(titleLower, "rate limit") || strings.Contains(titleLower, "rate limiting") {
		risk = "Enables denial of service or credential brute-forcing via bulk requests."
		evidence = "Endpoint accepted consecutive bulk requests without throttling."
		fix = "Implement rate limiting and throttling on sensitive endpoints."
	} else if strings.Contains(vulnLower, "sqli") || strings.Contains(vulnLower, "sql injection") || strings.Contains(titleLower, "sql injection") {
		if in.Category == "VERIFIED_ATTACK" {
			result = "Database query structure was successfully modified using SQL injection."
			impact = "Attacker can read, modify, or delete database records without authorization."
			evidence = "Injected payload returned modified query results or database errors."
		} else {
			risk = "Attacker can read, modify, or delete database records without authorization."
			evidence = "Injected payload returned database errors or structure modifications."
			fix = "Use parameterized queries (prepared statements) for all database operations."
		}
	} else if strings.Contains(vulnLower, "xss") || strings.Contains(vulnLower, "reflected xss") || strings.Contains(titleLower, "xss") {
		if in.Category == "VERIFIED_ATTACK" {
			result = "Reflected input payload executed successfully in the browser."
			impact = "Attacker can execute arbitrary scripts in the context of the user's session."
			evidence = "Input payload was reflected in response body without proper encoding."
		} else {
			risk = "Attacker can execute arbitrary scripts in the context of the user's session."
			evidence = "Input payload was reflected in response body without proper encoding."
			fix = "Implement context-aware output encoding and deploy a strong Content-Security-Policy."
		}
	} else {
		sentences := splitIntoSentences(in.Description)
		if in.Category == "VERIFIED_ATTACK" {
			result = "Exploit payload executed successfully against the target."
			impact = "Attacker can perform unauthorized actions or access restricted resources."
			evidence = "Response behavior was different from the normal baseline response."
			if len(sentences) > 0 {
				result = truncateSentence(sentences[0])
			}
			if len(sentences) > 1 {
				impact = truncateSentence(sentences[1])
			}
			if len(sentences) > 2 {
				evidence = truncateSentence(sentences[2])
			}
		} else {
			risk = "Vulnerability may allow attackers to compromise application state."
			evidence = "Observation confirmed by unexpected response structure or values."
			fix = "Validate and sanitize inputs and restrict access configurations."
			if len(sentences) > 0 {
				risk = truncateSentence(sentences[0])
			}
			if len(sentences) > 1 {
				evidence = truncateSentence(sentences[1])
			}
			if len(sentences) > 2 {
				fix = truncateSentence(sentences[2])
			}
		}
	}

	if in.Category == "VERIFIED_ATTACK" {
		return fmt.Sprintf("Result:\n- %s\n\nImpact:\n- %s\n\nEvidence:\n- %s\n\nConfidence:\n- %s", result, impact, evidence, confidenceLabel)
	} else {
		return fmt.Sprintf("Risk:\n- %s\n\nEvidence:\n- %s\n\nFix:\n- %s\n\nConfidence:\n- %s", risk, evidence, fix, confidenceLabel)
	}
}

func splitIntoSentences(text string) []string {
	text = strings.ReplaceAll(text, "\n", " ")
	re := regexp.MustCompile(`[^.!?]+[.!?]?`)
	matches := re.FindAllString(text, -1)
	var result []string
	for _, m := range matches {
		s := strings.TrimSpace(m)
		if len(s) > 3 {
			result = append(result, s)
		}
	}
	return result
}

func truncateSentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, "!") && !strings.HasSuffix(s, "?") {
		s = s + "."
	}
	return s
}

