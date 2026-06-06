package report

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sync"
	"time"

	"connectrpc.com/connect"
	aiv1 "github.com/parth/lastresort/internal/gen/ai/v1"
	"github.com/parth/lastresort/internal/gen/ai/v1/aiv1connect"
	"github.com/parth/lastresort/internal/storage"
)

type narrativeCacheEntry struct {
	description string
	remediation string
}

// Generator handles report compilation.
type Generator struct {
	db       *storage.DB
	aiClient aiv1connect.AiServiceClient

	cacheMu sync.RWMutex
	cache   map[string]narrativeCacheEntry
}

// NewGenerator instantiates a report Generator.
func NewGenerator(db *storage.DB, aiClient aiv1connect.AiServiceClient) *Generator {
	return &Generator{
		db:       db,
		aiClient: aiClient,
		cache:    make(map[string]narrativeCacheEntry),
	}
}

// GenerateScanReport queries a scan's details and outputs markdown/HTML report files.
func (g *Generator) GenerateScanReport(ctx context.Context, scanID string) (string, string, error) {
	// 1. Fetch scan information
	var targetURL, detectedTechs, authModel string
	var status, profile int
	var startedAtNull, finishedAtNull sql.NullTime

	err := g.db.QueryRowContext(ctx,
		`SELECT target_url, status, profile, started_at, finished_at, COALESCE(detected_technologies, ''), COALESCE(auth_model, '')
		 FROM scans WHERE id = ?`, scanID,
	).Scan(&targetURL, &status, &profile, &startedAtNull, &finishedAtNull, &detectedTechs, &authModel)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch scan for reporting: %w", err)
	}

	// 2. Fetch findings
	rows, err := g.db.QueryContext(ctx,
		`SELECT id, title, description, severity, vulnerability_type, endpoint, payload, response_status, confidence, category, is_false_positive, COALESCE(verification_id, '')
		 FROM findings WHERE scan_id = ? ORDER BY severity DESC, vulnerability_type`, scanID,
	)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch findings for reporting: %w", err)
	}
	defer rows.Close()

	var findings []storage.Finding
	severityCounts := map[string]int{"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	categoryCounts := map[string]int{"VERIFIED_ATTACK": 0, "ATTEMPT": 0, "OBSERVATION": 0, "HYPOTHESIS": 0}

	for rows.Next() {
		var f storage.Finding
		var isFP int
		var category sql.NullString
		err := rows.Scan(&f.ID, &f.Title, &f.Description, &f.Severity, &f.VulnerabilityType, &f.Endpoint, &f.Payload, &f.ResponseStatus, &f.Confidence, &category, &isFP, &f.VerificationID)
		if err != nil {
			return "", "", fmt.Errorf("failed to scan finding row: %w", err)
		}
		f.IsFalsePositive = isFP
		catStr := category.String
		switch catStr {
		case "VERIFIED_FINDING":
			catStr = "VERIFIED_ATTACK"
		case "POTENTIAL_FINDING":
			catStr = "HYPOTHESIS"
		case "FALSE_POSITIVE":
			catStr = "ATTEMPT"
		case "OBSERVATION":
			catStr = "OBSERVATION"
		case "":
			catStr = "OBSERVATION"
		}
		f.Category = catStr
		findings = append(findings, f)

		if isFP == 0 {
			severityCounts[f.Severity]++
			categoryCounts[f.Category]++
		}
	}


// HTMLFinding extends storage.Finding with narrative fields for template rendering.
type HTMLFinding struct {
	storage.Finding
	Description string
	Remediation string
	RawRequest  string
	RawResponse string
}


	// 2c. Fetch exploration stats
	var endpointCount int
	_ = g.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM endpoints WHERE scan_id = ?", scanID).Scan(&endpointCount)

	// 3. Build HTML findings list and execute single AI summary call
	var htmlFindings []HTMLFinding
	md := fmt.Sprintf("# Security Assessment Report for %s\n\n", targetURL)

	durationStr := "N/A"
	if startedAtNull.Valid && finishedAtNull.Valid {
		durationStr = finishedAtNull.Time.Sub(startedAtNull.Time).Truncate(time.Second).String()
	}

	var pbFindings []*aiv1.FindingSummary
	for _, f := range findings {
		descText := f.Description
		if descText == "" {
			descText = "No detailed description provided."
		}
		remedText := getRemediationText(f.VulnerabilityType)

		pbFindings = append(pbFindings, &aiv1.FindingSummary{
			Title:             f.Title,
			Severity:          f.Severity,
			VulnerabilityType: f.VulnerabilityType,
			Endpoint:          f.Endpoint,
			Confidence:        float32(f.Confidence),
		})

		// Fetch evidence from multiple sources (best available)
		var rawReq, rawRes string

		// Source 1: Attack Verification Artifacts
		if f.VerificationID != "" {
			if sv, err := g.db.GetVerificationForFinding(ctx, f.ID); err == nil && sv.ArtifactsJSON != "" {
				var artifacts []storage.EvidenceArtifact
				if err := json.Unmarshal([]byte(sv.ArtifactsJSON), &artifacts); err == nil {
					for _, art := range artifacts {
						if art.ArtifactType == "REQUEST" && rawReq == "" {
							rawReq = art.Content
						}
						if art.ArtifactType == "RESPONSE" && rawRes == "" {
							rawRes = art.Content
						}
					}
				}
			}
		}

		// Source 2: Finding Evidence (fallback)
		if rawReq == "" || rawRes == "" {
			var feReq, feRes string
			row := g.db.QueryRowContext(ctx, `
				SELECT request_excerpt, response_excerpt
				FROM finding_evidence
				WHERE finding_id = ?
				ORDER BY created_at ASC
				LIMIT 1
			`, f.ID)
			if err := row.Scan(&feReq, &feRes); err == nil {
				if rawReq == "" {
					rawReq = feReq
				}
				if rawRes == "" {
					rawRes = feRes
				}
			}
		}

		// Source 3: Attack Attempts (last resort)
		if rawReq == "" || rawRes == "" {
			var aaReq, aaRes string
			row := g.db.QueryRowContext(ctx, `
				SELECT request_captured, response_captured
				FROM attack_attempts
				WHERE scan_id = ? AND endpoint = ? AND payload = ?
				ORDER BY created_at DESC
				LIMIT 1
			`, scanID, f.Endpoint, f.Payload)
			if err := row.Scan(&aaReq, &aaRes); err == nil {
				if rawReq == "" {
					rawReq = aaReq
				}
				if rawRes == "" {
					rawRes = aaRes
				}
			}
		}

		if len(rawRes) > 2000 {
			rawRes = rawRes[:2000] + "\n...[TRUNCATED]..."
		}

		htmlFindings = append(htmlFindings, HTMLFinding{
			Finding:     f,
			Description: descText,
			Remediation: remedText,
			RawRequest:  rawReq,
			RawResponse: rawRes,
		})
	}

	// Single AI call for Executive Summary
	execSummary := "Automated security assessment complete. Please review the findings below for detailed analysis and remediation steps."
	riskRating := "MEDIUM"
	keyRecs := []string{
		"Apply input filtering and output encoding controls.",
		"Configure standard secure HTTP headers.",
		"Audit authentication mechanisms and authorization paths.",
	}

	if g.aiClient != nil && len(findings) > 0 {
		aiCtx, aiCancel := context.WithTimeout(ctx, 45*time.Second)
		aiReq := &aiv1.GenerateExecutiveSummaryRequest{
			TargetUrl:            targetURL,
			HighCount:            int32(severityCounts["HIGH"]),
			MediumCount:          int32(severityCounts["MEDIUM"]),
			LowCount:             int32(severityCounts["LOW"]),
			InfoCount:            int32(severityCounts["INFO"]),
			Findings:             pbFindings,
			Duration:             durationStr,
			DetectedTechnologies: detectedTechs,
		}
		startTime := time.Now()
		aiRes, err := g.aiClient.GenerateExecutiveSummary(aiCtx, connect.NewRequest(aiReq))
		aiCancel()
		duration := time.Since(startTime)

		if err == nil && aiRes.Msg.Summary != "" {
			execSummary = aiRes.Msg.Summary
			riskRating = aiRes.Msg.RiskRating
			keyRecs = aiRes.Msg.KeyRecommendations

			// Track Gemini call telemetry in DB
			_, _ = g.db.ExecContext(ctx,
				`UPDATE scans SET
					gemini_calls = COALESCE(gemini_calls, 0) + 1,
					gemini_time_ms = COALESCE(gemini_time_ms, 0) + ?
				 WHERE id = ?`,
				duration.Milliseconds(), scanID,
			)
		} else {
			// Fallback logic
			if severityCounts["HIGH"] > 0 {
				riskRating = "HIGH"
			}
		}
	}

	// Compile Markdown Report
	md += "## Executive Summary\n"
	md += fmt.Sprintf("%s\n\n", execSummary)
	md += fmt.Sprintf("- **Target URL:** %s\n", targetURL)
	md += fmt.Sprintf("- **Scan Status:** Completed\n")
	md += fmt.Sprintf("- **Duration:** %s\n", durationStr)
	md += fmt.Sprintf("- **Overall Risk Rating:** %s\n", riskRating)
	md += fmt.Sprintf("- **Endpoints Explored:** %d\n", endpointCount)
	md += fmt.Sprintf("- **Attack Scenarios Attempted:** %d\n", categoryCounts["ATTEMPT"]+categoryCounts["VERIFIED_ATTACK"])
	md += fmt.Sprintf("- **Successful Exploits:** %d\n", categoryCounts["VERIFIED_ATTACK"])
	md += fmt.Sprintf("- **Security Observations:** %d\n\n", categoryCounts["OBSERVATION"])

	md += "### Key Security Recommendations\n"
	for _, rec := range keyRecs {
		md += fmt.Sprintf("1. %s\n", rec)
	}
	md += "\n"

	md += "### Vulnerabilities Found by Severity\n"
	md += "| Severity | Count |\n"
	md += "|----------|-------|\n"
	md += fmt.Sprintf("| **HIGH** | %d |\n", severityCounts["HIGH"])
	md += fmt.Sprintf("| **MEDIUM** | %d |\n", severityCounts["MEDIUM"])
	md += fmt.Sprintf("| **LOW** | %d |\n", severityCounts["LOW"])
	md += fmt.Sprintf("| **INFO** | %d |\n\n", severityCounts["INFO"])

	md += "## Findings Details\n\n"
	if len(findings) == 0 {
		md += "No security vulnerabilities were identified during this assessment.\n"
	} else {
		for i, f := range htmlFindings {
			fpLabel := ""
			if f.IsFalsePositive == 1 {
				fpLabel = " [FALSE POSITIVE]"
			}
			md += fmt.Sprintf("### %d. %s (%s)%s\n", i+1, f.Title, f.Severity, fpLabel)
			md += fmt.Sprintf("- **Vulnerability Type:** %s\n", f.VulnerabilityType)
			md += fmt.Sprintf("- **Endpoint:** `%s`\n", f.Endpoint)
			if f.Payload != "" {
				md += fmt.Sprintf("- **Payload:** `%s`\n", f.Payload)
			}
			if f.ResponseStatus > 0 {
				md += fmt.Sprintf("- **Response Status:** %d\n", f.ResponseStatus)
			}
			md += fmt.Sprintf("- **Confidence:** %.2f\n\n", f.Confidence)
			md += "**Description:**\n"
			md += f.Description + "\n\n"
			md += "**Remediation:**\n"
			md += f.Remediation + "\n\n"
			if f.RawRequest != "" {
				md += "**Raw HTTP Request:**\n```http\n" + f.RawRequest + "\n```\n\n"
				md += "**Raw HTTP Response:**\n```http\n" + f.RawResponse + "\n```\n\n"
			}
			md += "---\n\n"
		}
	}

	// 4. Ensure reports directory exists
	reportsDir := filepath.Join("data", "reports", scanID)
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create reports directory: %w", err)
	}

	mdPath := filepath.Join(reportsDir, "report.md")
	if err := os.WriteFile(mdPath, []byte(md), 0644); err != nil {
		return "", "", fmt.Errorf("failed to write Markdown report: %w", err)
	}

	// 5. Generate HTML content using default template
	htmlPath := filepath.Join(reportsDir, "report.html")
	htmlFile, err := os.Create(htmlPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to create HTML report: %w", err)
	}
	defer htmlFile.Close()

	tmpl, err := template.New("report").Parse(DefaultHTMLTemplate)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse HTML template: %w", err)
	}

	type HTMLData struct {
		TargetURL      string
		TechStack      string
		AuthModel      string
		HighCount      int
		MediumCount    int
		LowCount       int
		InfoCount      int
		Findings       []HTMLFinding
		GeneratedAt    string
		ExecSummary    string
		RiskRating     string
		Recommendations []string
	}

	htmlData := HTMLData{
		TargetURL:       targetURL,
		TechStack:       detectedTechs,
		AuthModel:       authModel,
		HighCount:       severityCounts["HIGH"],
		MediumCount:     severityCounts["MEDIUM"],
		LowCount:        severityCounts["LOW"],
		InfoCount:       severityCounts["INFO"],
		Findings:        htmlFindings,
		GeneratedAt:     time.Now().Format(time.RFC1123),
		ExecSummary:     execSummary,
		RiskRating:      riskRating,
		Recommendations: keyRecs,
	}

	if err := tmpl.Execute(htmlFile, htmlData); err != nil {
		return "", "", fmt.Errorf("failed to compile HTML report: %w", err)
	}

	// 6. Save reports metadata to SQLite
	_, _ = g.db.SaveReport(ctx, scanID, "markdown", mdPath, "Scan Report for "+targetURL+" (Markdown)")
	_, _ = g.db.SaveReport(ctx, scanID, "html", htmlPath, "Scan Report for "+targetURL+" (HTML)")

	return mdPath, htmlPath, nil
}

func getRemediationText(vulnType string) string {
	switch vulnType {
	case "Reflected XSS":
		return "Implement context-aware output encoding (e.g., HTML-entity encode user input) and deploy a strong Content-Security-Policy."
	case "SQL Injection":
		return "Use parameterized queries (prepared statements) for all database operations and validate all user-supplied data."
	case "CSRF":
		return "Enforce anti-CSRF tokens on state-changing requests or use SameSite=Lax/Strict cookie attributes."
	case "CORS Misconfiguration":
		return "Restrict Access-Control-Allow-Origin to trusted domains and avoid using wildcard '*' with credentials."
	case "Security Misconfiguration":
		return "Enable missing security headers (CSP, HSTS, X-Frame-Options) to enhance browser-side protection."
	default:
		return "Review the observation and apply industry-standard security hardening based on the identified risk."
	}
}

// DefaultHTMLTemplate is a premium dark theme HTML template for report exports.
const DefaultHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Assessment Report for {{.TargetURL}}</title>
    <style>
        body {
            font-family: 'Segoe UI', Roboto, sans-serif;
            background-color: #0f172a;
            color: #e2e8f0;
            margin: 0;
            padding: 40px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: #1e293b;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
        }
        h1, h2, h3 {
            color: #f1f5f9;
        }
        h1 {
            border-bottom: 2px solid #334155;
            padding-bottom: 15px;
            margin-top: 0;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        .summary-card {
            background: #0f172a;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            border-top: 4px solid #334155;
        }
        .summary-card.high { border-top-color: #ef4444; }
        .summary-card.medium { border-top-color: #f97316; }
        .summary-card.low { border-top-color: #3b82f6; }
        .summary-card.info { border-top-color: #10b981; }
        .summary-val {
            font-size: 28px;
            font-weight: bold;
            color: #f8fafc;
        }
        .finding-card {
            background: #0f172a;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #334155;
        }
        .finding-card.HIGH { border-left-color: #ef4444; }
        .finding-card.MEDIUM { border-left-color: #f97316; }
        .finding-card.LOW { border-left-color: #3b82f6; }
        .finding-card.INFO { border-left-color: #10b981; }
        .finding-title {
            font-size: 20px;
            margin-top: 0;
            margin-bottom: 10px;
        }
        .meta-list {
            list-style: none;
            padding: 0;
            margin: 10px 0;
        }
        .meta-list li {
            font-size: 14px;
            color: #94a3b8;
            margin-bottom: 5px;
        }
        .meta-list li strong {
            color: #cbd5e1;
        }
        .code-block {
            background: #1e293b;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            overflow-x: auto;
            color: #38bdf8;
        }
        .footer {
            margin-top: 40px;
            text-align: center;
            font-size: 12px;
            color: #64748b;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>LastResort Vulnerability Assessment Report</h1>
        <p><strong>Target URL:</strong> {{.TargetURL}}</p>
        <p><strong>Technologies:</strong> {{.TechStack}} | <strong>Auth Model:</strong> {{.AuthModel}}</p>
        
        <h2>Executive Summary</h2>
        <p>{{.ExecSummary}}</p>
        <p><strong>Overall Risk Rating:</strong> {{.RiskRating}}</p>
        
        <h3>Key Security Recommendations:</h3>
        <ul>
            {{range .Recommendations}}
            <li>{{.}}</li>
            {{end}}
        </ul>

        <h2>Severity Summary</h2>
        <div class="summary-grid">
            <div class="summary-card high">
                <div class="summary-val">{{.HighCount}}</div>
                <div>HIGH</div>
            </div>
            <div class="summary-card medium">
                <div class="summary-val">{{.MediumCount}}</div>
                <div>MEDIUM</div>
            </div>
            <div class="summary-card low">
                <div class="summary-val">{{.LowCount}}</div>
                <div>LOW</div>
            </div>
            <div class="summary-card info">
                <div class="summary-val">{{.InfoCount}}</div>
                <div>INFO</div>
            </div>
        </div>

        <h2>Vulnerability Findings Details</h2>
        {{range .Findings}}
        <div class="finding-card {{.Severity}}">
            <div class="finding-title">{{.Title}} ({{.Severity}})</div>
            <ul class="meta-list">
                <li><strong>Vulnerability Type:</strong> {{.VulnerabilityType}}</li>
                <li><strong>Target Endpoint:</strong> {{.Endpoint}}</li>
                {{if .Payload}}
                <li><strong>Injection Payload:</strong> <span class="code-block">{{.Payload}}</span></li>
                {{end}}
                <li><strong>Confidence Score:</strong> {{.Confidence}}</li>
            </ul>
            <p><strong>Description:</strong></p>
            <p>{{.Description}}</p>
            <p><strong>Remediation:</strong></p>
            <p>{{.Remediation}}</p>
            {{if .RawRequest}}
            <p><strong>Raw HTTP Request:</strong></p>
            <pre class="code-block">{{.RawRequest}}</pre>
            {{end}}
            {{if .RawResponse}}
            <p><strong>Raw HTTP Response:</strong></p>
            <pre class="code-block">{{.RawResponse}}</pre>
            {{end}}
        </div>
        {{else}}
        <p>No vulnerabilities were identified during this assessment scan.</p>
        {{end}}

        <div class="footer">
            Generated by LastResort SecOps Engine on {{.GeneratedAt}}
        </div>
    </div>
</body>
</html>
`
