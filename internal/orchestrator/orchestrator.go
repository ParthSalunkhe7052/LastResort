package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/parth/lastresort/internal/browser"
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

func (o *Orchestrator) trackGeminiCall(ctx context.Context, scanID string, duration time.Duration) {
	if scanID == "" {
		return
	}
	_, _ = o.db.ExecContext(ctx,
		`UPDATE scans SET
			gemini_calls = COALESCE(gemini_calls, 0) + 1,
			gemini_time_ms = COALESCE(gemini_time_ms, 0) + ?
		 WHERE id = ?`,
		duration.Milliseconds(), scanID,
	)
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

		// Divide modules into prep, parallel (active tests), and completion phases
		var prepModules []string
		var parallelModules []string
		var completionModules []string

		for _, m := range modules {
			switch m {
			case ModuleRecon, ModuleAuthDiscovery, ModuleCrawlStatic, ModulePassive:
				prepModules = append(prepModules, m)
			case ModuleHeaders, ModuleCors, ModuleXssReflected, ModuleSqliBasic, ModuleCsrfBasic, ModuleRateLimitBasic, ModuleAiHypotheses:
				parallelModules = append(parallelModules, m)
			case ModuleReport:
				completionModules = append(completionModules, m)
			default:
				prepModules = append(prepModules, m)
			}
		}

		// 1. Preparation Phase (Sequential)
		for _, module := range prepModules {
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

			err := o.runModule(ctx, scanID, targetURL, module, as)
			completedAt := time.Now()
			if err != nil {
				o.publishModuleError(scanID, phaseName, err)
				log.Printf("[Orchestrator] [WARNING] Prep Module %s failed: %v", module, err)
				_ = o.db.UpsertScanModule(ctx, scanID, phaseName, storage.ModuleFailed, &startedAt, &completedAt, err.Error())
			} else {
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

		// 2. Active Testing Phase (Parallel Worker Pool)
		if len(parallelModules) > 0 {
			var mu sync.Mutex
			
			startParallelModule := func(module string) time.Time {
				mu.Lock()
				defer mu.Unlock()
				phaseName := moduleDisplayName(module)
				startedAt := time.Now()
				_ = o.db.UpsertScanModule(ctx, scanID, phaseName, storage.ModuleRunning, &startedAt, nil, "")
				o.publishPhaseStart(scanID, phaseName)
				return startedAt
			}

			updateParallelProgress := func(module string, startedAt time.Time, err error) {
				mu.Lock()
				defer mu.Unlock()
				
				phaseName := moduleDisplayName(module)
				completedAt := time.Now()
				if err != nil {
					o.publishModuleError(scanID, phaseName, err)
					log.Printf("[Orchestrator] [WARNING] Parallel Module %s failed: %v", module, err)
					_ = o.db.UpsertScanModule(ctx, scanID, phaseName, storage.ModuleFailed, &startedAt, &completedAt, err.Error())
				} else {
					_ = o.db.UpsertScanModule(ctx, scanID, phaseName, storage.ModuleSuccess, &startedAt, &completedAt, "")
				}
				
				o.publishPhaseCompleted(scanID, phaseName)
				cumulative += weights[module]
				if cumulative > 1.0 {
					cumulative = 1.0
				}
				o.publishProgress(scanID, cumulative)
				o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_RUNNING, cumulative)
				
				if isActiveScanModule(module) {
					o.emitNewFindings(ctx, scanID)
				}
			}

			numWorkers := 3
			if len(parallelModules) < numWorkers {
				numWorkers = len(parallelModules)
			}

			moduleChan := make(chan string, len(parallelModules))
			for _, m := range parallelModules {
				moduleChan <- m
			}
			close(moduleChan)

			var wg sync.WaitGroup
			for i := 0; i < numWorkers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for m := range moduleChan {
						startedAt := startParallelModule(m)
						err := o.runModule(ctx, scanID, targetURL, m, as)
						updateParallelProgress(m, startedAt, err)
					}
				}()
			}
			wg.Wait()
		}

		// 3. Completion Phase (Sequential)
		for _, module := range completionModules {
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

			err := o.runModule(ctx, scanID, targetURL, module, as)
			completedAt := time.Now()
			if err != nil {
				o.publishModuleError(scanID, phaseName, err)
				log.Printf("[Orchestrator] [WARNING] Completion Module %s failed: %v", module, err)
				_ = o.db.UpsertScanModule(ctx, scanID, phaseName, storage.ModuleFailed, &startedAt, &completedAt, err.Error())
			} else {
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
		successCount, failedCount, summaryErr := o.db.ModuleSummary(ctx, scanID)
		if summaryErr != nil {
			// Fallback to old any-failed check
			anyFailed, _ := o.db.AnyModuleFailed(ctx, scanID)
			if anyFailed {
				o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_FAILED, 1.0)
			} else {
				o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_COMPLETED, 1.0)
			}
		} else if failedCount > 0 && successCount > 0 {
			// Some modules ran successfully, some failed — partial success
			o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_COMPLETED, 1.0)
			GlobalBroker.Publish(Event{
				ScanID:    scanID,
				Type:      EventScanPartialSuccess,
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"succeeded": float64(successCount),
					"failed":    float64(failedCount),
				},
			})
		} else if failedCount > 0 {
			o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_FAILED, 1.0)
		} else {
			o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_COMPLETED, 1.0)
		}

		log.Printf("[Orchestrator] Scan completed: %s (ok=%d failed=%d)", scanID, successCount, failedCount)

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
	case ModuleAuthDiscovery:
		return "Autonomous Auth Discovery"
	case ModuleReport:
		return "Report Generation"
	default:
		return module
	}
}

func (o *Orchestrator) runModule(ctx context.Context, scanID, targetURL, module string, as *scanner.ActiveScanner) error {
	onLog := func(msg string) {
		GlobalBroker.Publish(Event{
			ScanID:    scanID,
			Type:      EventLogInfo,
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"message": msg,
				"module":  module,
			},
		})
	}

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
		start := time.Now()
		aiRes, err := o.aiClient.AnalyzeRecon(ctx, aiReq)
		o.trackGeminiCall(ctx, scanID, time.Since(start))
		if err != nil {
			return err
		}
		detectedTechs := strings.Join(aiRes.Msg.DetectedTechnologies, ", ")
		authModel := aiRes.Msg.AuthenticationModel
		_, err = o.db.ExecContext(ctx,
			"UPDATE scans SET detected_technologies = ?, auth_model = ? WHERE id = ?",
			detectedTechs, authModel, scanID,
		)
		if err != nil {
			return err
		}

		// Create Attack Goals from AI recommendations (Major Fix: Goal-Driven)
		for _, rec := range aiRes.Msg.RecommendedTests {
			goalType := storage.GoalAccessOtherUserData // default
			lowRec := strings.ToLower(rec)
			if strings.Contains(lowRec, "admin") {
				goalType = storage.GoalAccessAdminFunction
			} else if strings.Contains(lowRec, "privilege") {
				goalType = storage.GoalEscalatePrivileges
			} else if strings.Contains(lowRec, "data") || strings.Contains(lowRec, "export") {
				goalType = storage.GoalExportRestrictedData
			}

			_, _ = o.db.SaveGoal(ctx, scanID, goalType, rec, "Verified through AI exploration", "Confirmed by response analysis")
		}
		return nil

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
					Type:      EventHypothesisGenerated,
					Timestamp: time.Now(),
					Data: map[string]interface{}{
						"title":      res.Title,
						"confidence": float64(0.6),
						"source":     "csrf_heuristic",
						"status":     "GENERATED",
						"flow_id":    float64(flowID),
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
		start := time.Now()
		aiRes, err := o.aiClient.GenerateHypotheses(ctx, connect.NewRequest(&aiv1.GenerateHypothesesRequest{
			TargetUrl: targetURL,
			Endpoints: urls,
		}))
		o.trackGeminiCall(ctx, scanID, time.Since(start))
		if err != nil {
			return err
		}
		for _, h := range aiRes.Msg.Hypotheses {
			GlobalBroker.Publish(Event{
				ScanID:    scanID,
				Type:      EventHypothesisGenerated,
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
			
			// Execute Hypothesis (Major Fix: Adversarial Reasoning)
			go func(hyp *aiv1.Hypothesis) {
				execCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				
				endpoints, _ := o.db.ListEndpoints(execCtx, scanID)
				if len(endpoints) == 0 {
					return
				}

				// Focus on the first matching endpoint for now (can be expanded to all)
				targetEp := endpoints[0]
				
				// 1. Ask AI for specific payload
				payloadReq := connect.NewRequest(&aiv1.GenerateAttackPayloadRequest{
					HypothesisTitle:       hyp.Title,
					HypothesisDescription: hyp.Description,
					Endpoint:              targetEp.URL,
					Method:                targetEp.Method,
				})
				
				start := time.Now()
				payloadRes, err := o.aiClient.GenerateAttackPayload(execCtx, payloadReq)
				o.trackGeminiCall(execCtx, scanID, time.Since(start))
				if err != nil {
					log.Printf("[Orchestrator] AI Payload Gen Failed for %s: %v", hyp.Title, err)
					return
				}
				
				// 2. Execute the AI-crafted attack
				client := &http.Client{Timeout: 10 * time.Second}
				req, err := http.NewRequestWithContext(execCtx, payloadRes.Msg.Method, payloadRes.Msg.Url, strings.NewReader(payloadRes.Msg.Body))
				if err != nil {
					return
				}
				for k, v := range payloadRes.Msg.Headers {
					req.Header.Set(k, v)
				}
				
				resp, err := client.Do(req)
				if err != nil {
					return
				}
				respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
				resp.Body.Close()

				// 3. Save flow for evidence
				flowID, _ := o.db.SaveFlow(execCtx, scanID, payloadRes.Msg.Method, payloadRes.Msg.Url, req.Header, []byte(payloadRes.Msg.Body), resp.Header, respBytes, resp.StatusCode)
				
				// 4. Heuristic verification (simplistic for now)
				isVerified := false
				if resp.StatusCode >= 500 || strings.Contains(strings.ToLower(string(respBytes)), "sql") || strings.Contains(strings.ToLower(string(respBytes)), "alert(1)") {
					isVerified = true
				}
				
				if isVerified {
					_, _ = o.db.ExecContext(execCtx, "UPDATE hypotheses SET status = ? WHERE scan_id = ? AND title = ?", "VERIFIED", scanID, hyp.Title)
					
					// Save as a Finding
					_, _ = o.db.SaveFindingWithEvidence(execCtx, storage.FindingInput{
						ScanID:            scanID,
						Title:             "[AI-VERIFIED] " + hyp.Title,
						Description:       hyp.Description + "\n\nAI Explanation: " + payloadRes.Msg.Explanation,
						Severity:          "HIGH",
						VulnerabilityType: hyp.VulnerabilityType,
						Endpoint:          payloadRes.Msg.Url,
						Payload:           payloadRes.Msg.Body,
						ResponseStatus:    resp.StatusCode,
						Confidence:        0.9,
						Category:          "VERIFIED_ATTACK",
					}, storage.EvidenceInput{
						FlowID:          flowID,
						EvidenceType:    storage.EvidenceHTTPFlow,
						RequestExcerpt:  fmt.Sprintf("%s %s", payloadRes.Msg.Method, payloadRes.Msg.Url),
						ResponseExcerpt: string(respBytes),
					})
				} else {
					_, _ = o.db.ExecContext(execCtx, "UPDATE hypotheses SET status = ? WHERE scan_id = ? AND title = ?", "FAILED", scanID, hyp.Title)
				}
			}(h)
		}
		return nil

	case ModuleAuthDiscovery:
		onLog("[AGENT] Starting autonomous authentication discovery...")
		browserClient := browser.NewClient("")
		goal := "Identify login forms, discover authentication endpoints, and attempt to find valid login paths."

		maxSteps := 5
		for step := 1; step <= maxSteps; step++ {
			onLog(fmt.Sprintf("[AGENT] Step %d: Analyzing current page state...", step))

			// 1. Get current state (navigate to seed first if just starting)
			actionReq := browser.ActionRequest{
				ScanID:    scanID,
				URL:       targetURL, // Always ensure we are in scope
				Action:    "navigate",
				ProxyPort: o.proxyPort,
			}
			if step > 1 {
				actionReq.URL = "" // Don't re-navigate, just get current source
				actionReq.Action = "wait"
			}

			actionRes, err := browserClient.ExecuteAction(ctx, actionReq)
			if err != nil {
				onLog(fmt.Sprintf("[AGENT] [ERROR] Browser action failed: %v", err))
				break
			}

			// 2. Ask AI what to do next
			decideReq := connect.NewRequest(&aiv1.DecideBrowserActionRequest{
				Url:         targetURL,
				PageSource:  actionRes.PageSource,
				CurrentGoal: goal,
			})

			start := time.Now()
			decideRes, err := o.aiClient.DecideBrowserAction(ctx, decideReq)
			o.trackGeminiCall(ctx, scanID, time.Since(start))
			if err != nil {
				onLog(fmt.Sprintf("[AGENT] [ERROR] AI Decision failed: %v", err))
				break
			}

			onLog(fmt.Sprintf("[AGENT] AI Decision: %s (%s)", decideRes.Msg.Action, decideRes.Msg.Explanation))

			if decideRes.Msg.Action == "finish" {
				onLog("[AGENT] AI signaling discovery phase complete.")
				break
			}

			// 3. Execute the AI decided action
			execReq := browser.ActionRequest{
				ScanID:    scanID,
				Action:    decideRes.Msg.Action,
				Selector:  decideRes.Msg.Selector,
				Value:     decideRes.Msg.Value,
				ProxyPort: o.proxyPort,
			}

			_, err = browserClient.ExecuteAction(ctx, execReq)
			if err != nil {
				onLog(fmt.Sprintf("[AGENT] [ERROR] Execution of %s failed: %v", decideRes.Msg.Action, err))
			}

			// Small delay for animations
			time.Sleep(2 * time.Second)
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

// isActiveScanModule returns true for modules that generate findings via HTTP probes.
func isActiveScanModule(module string) bool {
	switch module {
	case ModuleHeaders, ModuleCors, ModuleXssReflected, ModuleSqliBasic, ModuleRateLimitBasic:
		return true
	}
	return false
}

// emitNewFindings queries findings added since we started tracking and publishes finding.new events.
// We use a simple approach: query the most recent findings for this scan and emit them.
func (o *Orchestrator) emitNewFindings(ctx context.Context, scanID string) {
	rows, err := o.db.QueryContext(ctx,
		`SELECT id, title, severity, vulnerability_type, endpoint, confidence, category
		 FROM findings WHERE scan_id = ? AND is_false_positive = 0
		 ORDER BY created_at DESC LIMIT 50`, scanID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id, title, severity, vulnType, endpoint, category string
		var confidence float64
		if err := rows.Scan(&id, &title, &severity, &vulnType, &endpoint, &confidence, &category); err != nil {
			continue
		}
		GlobalBroker.Publish(Event{
			ScanID:    scanID,
			Type:      EventFindingNew,
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"id":               id,
				"title":            title,
				"severity":         severity,
				"vulnerability_type": vulnType,
				"endpoint":         endpoint,
				"confidence":       confidence,
				"category":         category,
			},
		})
	}
}
