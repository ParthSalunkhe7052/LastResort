package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/parth/lastresort/internal/crawler"
	aiv1 "github.com/parth/lastresort/internal/gen/ai/v1"
	"github.com/parth/lastresort/internal/gen/ai/v1/aiv1connect"
	scanv1 "github.com/parth/lastresort/internal/gen/scan/v1"
	"github.com/parth/lastresort/internal/report"
	"github.com/parth/lastresort/internal/scanner"
	"github.com/parth/lastresort/internal/storage"
	"google.golang.org/protobuf/types/known/structpb"
)

// Orchestrator manages background execution of scan phases
type Orchestrator struct {
	db        *storage.DB
	aiClient  aiv1connect.AiServiceClient
	proxyPort int
}

// NewOrchestrator instantiates a new Orchestrator
func NewOrchestrator(db *storage.DB, aiClient aiv1connect.AiServiceClient, proxyPort int) *Orchestrator {
	return &Orchestrator{
		db:        db,
		aiClient:  aiClient,
		proxyPort: proxyPort,
	}
}

// Start spawns a background goroutine to execute the scan sequence
func (o *Orchestrator) Start(scanID string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		log.Printf("[Orchestrator] Launching background scan execution for Scan ID: %s", scanID)

		// 1. Fetch Scan details from SQLite
		var targetURL string
		var profileInt int
		err := o.db.QueryRowContext(ctx, "SELECT target_url, profile FROM scans WHERE id = ?", scanID).Scan(&targetURL, &profileInt)
		if err != nil {
			log.Printf("[Orchestrator] [ERROR] Failed to load scan %s: %v", scanID, err)
			o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_FAILED, 0.0)
			return
		}

		profile := scanv1.ScanProfile(profileInt)
		modules, ok := ProfileModules[profile]
		if !ok || len(modules) == 0 {
			// Default to STANDARD behavior if profile is unknown.
			modules = ProfileModules[scanv1.ScanProfile_SCAN_PROFILE_STANDARD]
		}

		// Initialize module tracking to PENDING
		for _, module := range modules {
			_ = o.db.UpsertScanModule(ctx, scanID, moduleDisplayName(module), storage.ModulePending, nil, nil, "")
		}
		weights := GetModuleWeights(modules)
		cumulative := 0.0

		// Update database status to Running
		o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_RUNNING, 0.0)
		o.publishProgress(scanID, 0.0)
		GlobalBroker.Publish(Event{
			ScanID:    scanID,
			Type:      EventScanStarted,
			Timestamp: time.Now(),
		})

		as := scanner.NewActiveScanner(o.db)

		for _, module := range modules {
			select {
			case <-ctx.Done():
				o.failScan(scanID, fmt.Errorf("scan context cancelled: %w", ctx.Err()))
				return
			default:
			}

			phaseName := moduleDisplayName(module)
			o.publishPhaseStart(scanID, phaseName)
			startedAt := time.Now()
			_ = o.db.UpsertScanModule(ctx, scanID, phaseName, storage.ModuleRunning, &startedAt, nil, "")

			if err := o.runModule(ctx, scanID, targetURL, module, as); err != nil {
				// Keep local-first behavior: modules can fail without hard aborting, but we surface it.
				o.publishModuleError(scanID, phaseName, err)
				log.Printf("[Orchestrator] [WARNING] Module %s failed/partial: %v", module, err)
				completedAt := time.Now()
				_ = o.db.UpsertScanModule(ctx, scanID, phaseName, storage.ModuleFailed, &startedAt, &completedAt, err.Error())
			} else {
				completedAt := time.Now()
				_ = o.db.UpsertScanModule(ctx, scanID, phaseName, storage.ModuleSuccess, &startedAt, &completedAt, "")
			}

			o.publishPhaseCompleted(scanID, phaseName)
			cumulative += weights[module]
			if cumulative > 1.0 {
				cumulative = 1.0
			}
			o.publishProgress(scanID, cumulative)
			o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_RUNNING, cumulative)
		}

		// --- WORKFLOW COMPLETION ---
		o.publishProgress(scanID, 1.0)
		anyFailed, err := o.db.AnyModuleFailed(ctx, scanID)
		if err != nil {
			anyFailed = true
		}
		if anyFailed {
			o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_FAILED, 1.0)
		} else {
			o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_COMPLETED, 1.0)
		}

		log.Printf("[Orchestrator] Scan completed successfully: %s", scanID)

		GlobalBroker.Publish(Event{
			ScanID:    scanID,
			Type:      EventScanCompleted,
			Timestamp: time.Now(),
		})
	}()
}

func (o *Orchestrator) updateScanStatus(scanID string, status scanv1.ScanStatus, progress float64) {
	var finishedAt interface{}
	var startedAt interface{}
	
	now := time.Now()
	if status == scanv1.ScanStatus_SCAN_STATUS_RUNNING {
		startedAt = now
	}
	if status == scanv1.ScanStatus_SCAN_STATUS_COMPLETED || status == scanv1.ScanStatus_SCAN_STATUS_FAILED {
		finishedAt = now
	}

	query := "UPDATE scans SET status = ?, progress = ? "
	args := []interface{}{status, progress}

	if startedAt != nil {
		query += ", started_at = ?"
		args = append(args, startedAt)
	}
	if finishedAt != nil {
		query += ", finished_at = ?"
		args = append(args, finishedAt)
	}

	query += " WHERE id = ?"
	args = append(args, scanID)

	_, err := o.db.Exec(query, args...)
	if err != nil {
		log.Printf("[Orchestrator] [ERROR] Failed to update scan status in DB: %v", err)
	}
}

func (o *Orchestrator) publishProgress(scanID string, progress float64) {
	structVal, _ := structpb.NewStruct(map[string]interface{}{
		"progress": progress,
	})

	GlobalBroker.Publish(Event{
		ScanID:    scanID,
		Type:      EventProgress,
		Timestamp: time.Now(),
		Data:      structVal.AsMap(),
	})
}

func (o *Orchestrator) publishPhaseStart(scanID string, phaseName string) {
	structVal, _ := structpb.NewStruct(map[string]interface{}{
		"phase": phaseName,
	})

	GlobalBroker.Publish(Event{
		ScanID:    scanID,
		Type:      EventPhaseStarted,
		Timestamp: time.Now(),
		Data:      structVal.AsMap(),
	})
}

func (o *Orchestrator) publishPhaseCompleted(scanID string, phaseName string) {
	structVal, _ := structpb.NewStruct(map[string]interface{}{
		"phase": phaseName,
	})

	GlobalBroker.Publish(Event{
		ScanID:    scanID,
		Type:      EventPhaseCompleted,
		Timestamp: time.Now(),
		Data:      structVal.AsMap(),
	})
}

func (o *Orchestrator) failScan(scanID string, err error) {
	log.Printf("[Orchestrator] [ERROR] Scan failed: %s: %v", scanID, err)
	o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_FAILED, 0.0)
	o.publishModuleError(scanID, "Scan Failed", err)
	GlobalBroker.Publish(Event{
		ScanID:    scanID,
		Type:      EventScanCompleted,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"status": "FAILED",
		},
	})
}

func (o *Orchestrator) publishModuleError(scanID, phaseName string, err error) {
	structVal, _ := structpb.NewStruct(map[string]interface{}{
		"phase":   phaseName,
		"error":   err.Error(),
		"severity": "ERROR",
	})
	GlobalBroker.Publish(Event{
		ScanID:    scanID,
		Type:      "module.error",
		Timestamp: time.Now(),
		Data:      structVal.AsMap(),
	})
}

func moduleDisplayName(module string) string {
	switch module {
	case ModuleRecon:
		return "Reconnaissance"
	case ModuleCrawlStatic:
		return "Crawling"
	case ModulePassive:
		return "Passive Analysis"
	case ModuleHeaders:
		return "Header Checks"
	case ModuleCors:
		return "CORS Checks"
	case ModuleXssReflected:
		return "Active Scan: XSS"
	case ModuleSqliBasic:
		return "Active Scan: SQLi"
	case ModuleCsrfBasic:
		return "Active Scan: CSRF"
	case ModuleRateLimitBasic:
		return "Active Scan: Rate Limiting"
	case ModuleAiHypotheses:
		return "AI Analysis"
	case ModuleReport:
		return "Report Generation"
	default:
		return module
	}
}

func (o *Orchestrator) runModule(ctx context.Context, scanID, targetURL, module string, as *scanner.ActiveScanner) error {
	switch module {
	case ModuleRecon:
		reconData, err := scanner.RunRecon(ctx, targetURL)
		if err != nil {
			return err
		}
		if o.aiClient == nil {
			return nil
		}

		aiReq := connect.NewRequest(&aiv1.AnalyzeReconRequest{
			TargetUrl:   targetURL,
			Headers:     reconData.Headers,
			CookieNames: reconData.Cookies,
		})
		aiRes, err := o.aiClient.AnalyzeRecon(ctx, aiReq)
		if err != nil {
			return err
		}
		detectedTechs := strings.Join(aiRes.Msg.DetectedTechnologies, ", ")
		authModel := aiRes.Msg.AuthenticationModel
		_, err = o.db.ExecContext(ctx,
			"UPDATE scans SET detected_technologies = ?, auth_model = ? WHERE id = ?",
			detectedTechs, authModel, scanID,
		)
		return err

	case ModuleCrawlStatic:
		cm := crawler.NewCrawlManager(scanID, o.proxyPort)
		return cm.Crawl(ctx, scanID, targetURL, func(msg string) {
			// Stream crawl activity as INFO logs (never as findings).
			GlobalBroker.Publish(Event{
				ScanID:    scanID,
				Type:      "log.info",
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"message":  msg,
				},
			})
		}, func(method, urlStr, source string) {
			_, err := o.db.SaveEndpoint(ctx, scanID, method, urlStr, source, 200, "text/html")
			if err != nil {
				log.Printf("[Orchestrator] [ERROR] Failed to save endpoint %s %s: %v", method, urlStr, err)
			}
		})

	case ModulePassive:
		// Passive analysis runs continuously in the proxy during crawl traffic capture.
		return nil

	case ModuleHeaders:
		endpoints, err := o.db.ListEndpoints(ctx, scanID)
		if err != nil {
			return err
		}
		for _, ep := range endpoints {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL, nil)
			if err != nil {
				continue
			}
			resp, err := as.GetHTTPClient().Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			_ = as.ScanHeaders(ctx, scanID, ep.URL, resp.Header, resp.StatusCode)
		}
		return nil

	case ModuleCors:
		endpoints, err := o.db.ListEndpoints(ctx, scanID)
		if err != nil {
			return err
		}
		for _, ep := range endpoints {
			_ = as.ScanCORS(ctx, scanID, ep.URL)
		}
		return nil

	case ModuleRateLimitBasic:
		// Prefer root target URL.
		return as.ScanRateLimit(ctx, scanID, targetURL)

	case ModuleXssReflected:
		endpoints, err := o.db.ListEndpoints(ctx, scanID)
		if err != nil {
			return err
		}
		for _, ep := range endpoints {
			// Only meaningful when there are insertion points.
			points, _ := scanner.ExtractInsertionPoints(ep.Method, ep.URL, nil, "")
			if len(points) == 0 {
				continue
			}
			_ = as.ScanXSS(ctx, scanID, ep.Method, ep.URL, nil, "")
		}
		return nil

	case ModuleSqliBasic:
		// 1) Run query-based SQLi checks on endpoints with query params.
		endpoints, err := o.db.ListEndpoints(ctx, scanID)
		if err != nil {
			return err
		}
		for _, ep := range endpoints {
			points, _ := scanner.ExtractInsertionPoints(ep.Method, ep.URL, nil, "")
			if len(points) == 0 {
				continue
			}
			_ = as.ScanSQLi(ctx, scanID, ep.Method, ep.URL, nil, "")
		}

		// 2) Run body-based SQLi checks on captured flows (POST/PUT/PATCH/DELETE).
		rows, err := o.db.QueryContext(ctx, "SELECT method, url, request_headers, request_body FROM http_flows WHERE scan_id = ? ORDER BY id DESC", scanID)
		if err != nil {
			return nil
		}
		defer rows.Close()
		for rows.Next() {
			var method, urlStr string
			var headersJSON string
			var body []byte
			if err := rows.Scan(&method, &urlStr, &headersJSON, &body); err != nil {
				continue
			}
			contentType := ""
			var hdrMap map[string][]string
			if json.Unmarshal([]byte(headersJSON), &hdrMap) == nil {
				if vals, ok := hdrMap["Content-Type"]; ok && len(vals) > 0 {
					contentType = vals[0]
				} else if vals, ok := hdrMap["content-type"]; ok && len(vals) > 0 {
					contentType = vals[0]
				}
			}
			_ = as.ScanSQLi(ctx, scanID, method, urlStr, body, contentType)
		}
		return nil

	case ModuleCsrfBasic:
		rows, err := o.db.QueryContext(ctx, "SELECT id, method, url, request_headers, request_body FROM http_flows WHERE scan_id = ? ORDER BY id DESC", scanID)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var flowID int64
			var method, urlStr string
			var headersJSON string
			var body []byte
			if err := rows.Scan(&flowID, &method, &urlStr, &headersJSON, &body); err != nil {
				continue
			}

			reqHeaders := make(http.Header)
			var hdrMap map[string][]string
			if json.Unmarshal([]byte(headersJSON), &hdrMap) == nil {
				for k, v := range hdrMap {
					for _, vv := range v {
						reqHeaders.Add(k, vv)
					}
				}
			}
			contentType := reqHeaders.Get("Content-Type")
			res, err := scanner.DetectCSRFHeuristic(method, urlStr, reqHeaders, body, contentType)
			if err != nil {
				continue
			}
			if res != nil && res.Suspected {
				_, _ = o.db.SaveHypothesis(ctx, scanID, res.Title, res.Reason, "csrf_heuristic", 0.6, storage.HypothesisGenerated)
				GlobalBroker.Publish(Event{
					ScanID:    scanID,
					Type:      "hypothesis.generated",
					Timestamp: time.Now(),
					Data: map[string]interface{}{
						"title":       res.Title,
						"confidence":  float64(0.6),
						"source":      "csrf_heuristic",
						"status":      "GENERATED",
						"flow_id":     float64(flowID),
					},
				})
			}
		}
		return nil

	case ModuleAiHypotheses:
		if o.aiClient == nil {
			return nil
		}
		endpoints, err := o.db.ListEndpoints(ctx, scanID)
		if err != nil {
			return err
		}
		var urls []string
		for _, ep := range endpoints {
			urls = append(urls, ep.URL)
		}
		aiRes, err := o.aiClient.GenerateHypotheses(ctx, connect.NewRequest(&aiv1.GenerateHypothesesRequest{
			TargetUrl: targetURL,
			Endpoints: urls,
		}))
		if err != nil {
			return err
		}
		for _, h := range aiRes.Msg.Hypotheses {
			GlobalBroker.Publish(Event{
				ScanID:    scanID,
				Type:      "hypothesis.generated",
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"title":       h.Title,
					"description": h.Description,
					"confidence":  float64(h.Confidence),
					"type":        h.VulnerabilityType,
					"source":      "ai",
					"status":      "GENERATED",
				},
			})
			_, _ = o.db.SaveHypothesis(ctx, scanID, h.Title, h.Description, "ai", float64(h.Confidence), storage.HypothesisGenerated)
		}
		return nil

	case ModuleReport:
		gen := report.NewGenerator(o.db, o.aiClient)
		_, htmlPath, err := gen.GenerateScanReport(ctx, scanID)
		if err != nil {
			return err
		}
		GlobalBroker.Publish(Event{
			ScanID:    scanID,
			Type:      "report.generated",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"path": htmlPath,
			},
		})
		return nil

	default:
		return nil
	}
}

func severityFromConfidence(conf float64) string {
	switch {
	case conf >= 0.9:
		return "HIGH"
	case conf >= 0.7:
		return "MEDIUM"
	case conf >= 0.4:
		return "LOW"
	default:
		return "INFO"
	}
}
