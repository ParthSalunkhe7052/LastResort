package report

import (
	"context"
	"database/sql"
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
		`SELECT id, title, description, severity, vulnerability_type, endpoint, payload, response_status, confidence, category, is_false_positive
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
		err := rows.Scan(&f.ID, &f.Title, &f.Description, &f.Severity, &f.VulnerabilityType, &f.Endpoint, &f.Payload, &f.ResponseStatus, &f.Confidence, &category, &isFP)
		if err != nil {
			return "", "", fmt.Errorf("failed to scan finding row: %w", err)
		}
		f.IsFalsePositive = isFP
		f.Category = category.String
		if f.Category == "" {
			f.Category = "OBSERVATION"
		}
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

	// 2b. Fetch hypotheses
	hyps, err := g.db.ListHypotheses(ctx, scanID)
	if err == nil {
		for _, h := range hyps {
			categoryCounts["HYPOTHESIS"]++
			// Map hypothesis to finding for reporting
			findings = append(findings, storage.Finding{
				ID:                h.ID,
				Title:             h.Title,
				Description:       h.Description,
				Severity:          "INFO",
				VulnerabilityType: "Hypothesis",
				Endpoint:          "N/A",
				Confidence:        h.Confidence,
				Category:          "HYPOTHESIS",
				CreatedAt:         h.CreatedAt,
			})
		}
	}

	// 2c. Fetch exploration stats
	var endpointCount int
	_ = g.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM endpoints WHERE scan_id = ?", scanID).Scan(&endpointCount)

	// 3. Build Markdown content and HTML findings list
	var htmlFindings []HTMLFinding
	md := fmt.Sprintf("# Security Assessment Report for %s\n\n", targetURL)
	md += "## Executive Summary\n"
	md += fmt.Sprintf("- **Target URL:** %s\n", targetURL)
	md += fmt.Sprintf("- **Scan Status:** Completed\n")
	md += fmt.Sprintf("- **Endpoints Explored:** %d\n", endpointCount)
	md += fmt.Sprintf("- **Attack Scenarios Attempted:** %d\n", categoryCounts["ATTEMPT"]+categoryCounts["VERIFIED_ATTACK"])
	md += fmt.Sprintf("- **Successful Exploits:** %d\n", categoryCounts["VERIFIED_ATTACK"])
	md += fmt.Sprintf("- **Security Observations:** %d\n", categoryCounts["OBSERVATION"])
	md += fmt.Sprintf("- **AI Hypotheses:** %d\n", categoryCounts["HYPOTHESIS"])

	if startedAtNull.Valid && finishedAtNull.Valid {
		duration := finishedAtNull.Time.Sub(startedAtNull.Time).Truncate(time.Second)
		md += fmt.Sprintf("- **Duration:** %s\n", duration.String())
	}
	md += "\n"

	md += "### Vulnerabilities Found by Severity\n"
	md += "| Severity | Count |\n"
	md += "|----------|-------|\n"
	md += fmt.Sprintf("| **HIGH** | %d |\n", severityCounts["HIGH"])
	md += fmt.Sprintf("| **MEDIUM** | %d |\n", severityCounts["MEDIUM"])
	md += fmt.Sprintf("| **LOW** | %d |\n", severityCounts["LOW"])
	md += fmt.Sprintf("| **INFO** | %d |\n\n", severityCounts["INFO"])

	md += "## Findings\n\n"
	if len(findings) == 0 {
		md += "No security vulnerabilities were identified during this assessment.\n"
	} else {
		for i, f := range findings {
			fpLabel := ""
			if f.IsFalsePositive == 1 {
				fpLabel = " [FALSE POSITIVE]"
			}

			descText := f.Description
			remedText := getRemediationText(f.VulnerabilityType)

			// Query AI narrative with 30s timeout
			if g.aiClient != nil {
				cacheKey := f.VulnerabilityType + "|" + f.Title
				g.cacheMu.RLock()
				cached, found := g.cache[cacheKey]
				g.cacheMu.RUnlock()

				if found {
					descText = cached.description
					remedText = cached.remediation
				} else {
					aiCtx, aiCancel := context.WithTimeout(ctx, 30*time.Second)
					aiReq := &aiv1.GenerateFindingNarrativeRequest{
						VulnerabilityType: f.VulnerabilityType,
						Title:             f.Title,
						Endpoint:          f.Endpoint,
						Evidence:          f.Payload,
						Confidence:        float32(f.Confidence),
					}
					startTime := time.Now()
					aiRes, err := g.aiClient.GenerateFindingNarrative(aiCtx, connect.NewRequest(aiReq))
					aiCancel()
					duration := time.Since(startTime)

					if err == nil && aiRes.Msg.Description != "" && aiRes.Msg.Remediation != "" {
						descText = aiRes.Msg.Description
						remedText = aiRes.Msg.Remediation

						g.cacheMu.Lock()
						g.cache[cacheKey] = narrativeCacheEntry{
							description: descText,
							remediation: remedText,
						}
						g.cacheMu.Unlock()
					}

					// Track Gemini call telemetry in DB
					_, _ = g.db.ExecContext(ctx,
						`UPDATE scans SET
							gemini_calls = COALESCE(gemini_calls, 0) + 1,
							gemini_time_ms = COALESCE(gemini_time_ms, 0) + ?
						 WHERE id = ?`,
						duration.Milliseconds(), scanID,
					)
				}
			}

			// Fetch evidence flows
			var rawReq, rawRes string
			row := g.db.QueryRowContext(ctx, `
				SELECT f.method, f.url, f.request_headers, f.request_body, f.response_headers, f.response_body
				FROM finding_evidence e
				JOIN http_flows f ON e.flow_id = f.id
				WHERE e.finding_id = ?
				LIMIT 1
			`, f.ID)
			
			var fMethod, fUrl, fReqHeaders, fResHeaders string
			var fReqBody, fResBody []byte
			if err := row.Scan(&fMethod, &fUrl, &fReqHeaders, &fReqBody, &fResHeaders, &fResBody); err == nil {
				rawReq = fmt.Sprintf("%s %s HTTP/1.1\n%s\n\n%s", fMethod, fUrl, fReqHeaders, string(fReqBody))
				rawRes = fmt.Sprintf("HTTP/1.1 %d\n%s\n\n%s", f.ResponseStatus, fResHeaders, string(fResBody))
				if len(rawRes) > 2000 {
					rawRes = rawRes[:2000] + "\n...[TRUNCATED]..."
				}
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
			md += descText + "\n\n"
			md += "**Remediation:**\n"
			md += remedText + "\n\n"
			if rawReq != "" {
				md += "**Raw HTTP Request:**\n```http\n" + rawReq + "\n```\n\n"
				md += "**Raw HTTP Response:**\n```http\n" + rawRes + "\n```\n\n"
			}
			md += "---\n\n"

			htmlFindings = append(htmlFindings, HTMLFinding{
				Finding:     f,
				Description: descText,
				Remediation: remedText,
				RawRequest:  rawReq,
				RawResponse: rawRes,
			})
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
	}

	htmlData := HTMLData{
		TargetURL:   targetURL,
		TechStack:   detectedTechs,
		AuthModel:   authModel,
		HighCount:   severityCounts["HIGH"],
		MediumCount: severityCounts["MEDIUM"],
		LowCount:    severityCounts["LOW"],
		InfoCount:   severityCounts["INFO"],
		Findings:    htmlFindings,
		GeneratedAt: time.Now().Format(time.RFC1123),
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
