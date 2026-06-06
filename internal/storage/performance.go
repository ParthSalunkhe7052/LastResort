package storage

import (
	"context"
	"database/sql"
	"time"
)

type ScanPerformanceMetrics struct {
	PagesCrawled          int     `json:"visited_pages"`
	EndpointsFound        int     `json:"endpoints_found"`
	FormsFound            int     `json:"forms_found"`
	AttackAttempts        int     `json:"fuzz_requests"`
	SuccessfulAttacks     int     `json:"successful_attacks"`
	FailedAttempts        int     `json:"failed_attempts"`
	Observations          int     `json:"observations"`
	ScanDuration          float64 `json:"elapsed_seconds"`
	GeminiCalls           int     `json:"gemini_calls"`
	AverageResponseTime   float64 `json:"average_response_time"`
	ReconDuration         float64 `json:"recon_duration"`
	CrawlDuration         float64 `json:"crawl_duration"`
	AttackTestingDuration float64 `json:"attack_testing_duration"`
	AiAnalysisDuration    float64 `json:"ai_analysis_duration"`
	ReportDuration        float64 `json:"report_duration"`
}

func (db *DB) GetScanPerformance(ctx context.Context, scanID string) (*ScanPerformanceMetrics, error) {
	metrics := &ScanPerformanceMetrics{}

	// Discovery and Inventory
	_ = db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT url) FROM endpoints WHERE scan_id = ? AND source = 'crawler'", scanID).Scan(&metrics.PagesCrawled)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM endpoints WHERE scan_id = ?", scanID).Scan(&metrics.EndpointsFound)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM forms WHERE scan_id = ?", scanID).Scan(&metrics.FormsFound)

	// Findings and Fuzzing Metrics
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE scan_id = ? AND category = 'VERIFIED_FINDING'", scanID).Scan(&metrics.SuccessfulAttacks)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE scan_id = ? AND category = 'POTENTIAL_FINDING'", scanID).Scan(&metrics.FailedAttempts)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE scan_id = ? AND category = 'OBSERVATION'", scanID).Scan(&metrics.Observations)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM attack_attempts WHERE scan_id = ?", scanID).Scan(&metrics.AttackAttempts)

	// Execution Metadata
	var startedAtNull, finishedAtNull sql.NullTime
	var geminiCalls, geminiTimeMs int
	err := db.QueryRowContext(ctx, "SELECT started_at, finished_at, COALESCE(gemini_calls, 0), COALESCE(gemini_time_ms, 0) FROM scans WHERE id = ?", scanID).Scan(&startedAtNull, &finishedAtNull, &geminiCalls, &geminiTimeMs)
	if err == nil {
		metrics.GeminiCalls = geminiCalls
		if geminiCalls > 0 {
			metrics.AverageResponseTime = float64(geminiTimeMs) / float64(geminiCalls)
		}
		if startedAtNull.Valid {
			if finishedAtNull.Valid {
				metrics.ScanDuration = finishedAtNull.Time.Sub(startedAtNull.Time).Seconds()
			} else {
				metrics.ScanDuration = time.Since(startedAtNull.Time).Seconds()
			}
		}
	}

	// Phase-specific Timing Breakdown
	rows, err := db.QueryContext(ctx, "SELECT module_name, started_at, completed_at FROM scan_modules WHERE scan_id = ?", scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			var start, end sql.NullTime
			if err := rows.Scan(&name, &start, &end); err == nil && start.Valid && end.Valid {
				dur := end.Time.Sub(start.Time).Seconds()
				switch name {
				case "Reconnaissance":
					metrics.ReconDuration = dur
				case "Crawling", "Autonomous Auth Discovery":
					metrics.CrawlDuration += dur
				case "Active Scan: XSS", "Active Scan: SQLi", "Active Scan: CSRF", "Active Scan: Rate Limiting", "Header Checks", "CORS Checks", "Passive Analysis":
					metrics.AttackTestingDuration += dur
				case "AI Analysis":
					metrics.AiAnalysisDuration = dur
				case "Report Generation":
					metrics.ReportDuration = dur
				}
			}
		}
	}

	return metrics, nil
}
