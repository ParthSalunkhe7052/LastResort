package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/parth/lastresort/internal/ai"
	"github.com/parth/lastresort/internal/browser"
	"github.com/parth/lastresort/internal/crawler"
	"github.com/parth/lastresort/internal/gen/ai/v1/aiv1connect"
	scanv1 "github.com/parth/lastresort/internal/gen/scan/v1"
	"github.com/parth/lastresort/internal/report"
	"github.com/parth/lastresort/internal/attack"
	"github.com/parth/lastresort/internal/scanner"
	"github.com/parth/lastresort/internal/storage"
	"google.golang.org/protobuf/types/known/structpb"
)

// Orchestrator manages background execution of scan phases
type Orchestrator struct {
	db            *storage.DB
	aiClient      aiv1connect.AiServiceClient // used only for final report summary
	browserClient *browser.Client
	proxyPort     int
	verification  *VerificationEngine
	browserMu     sync.Mutex
	profile       scanv1.ScanProfile
}

// NewOrchestrator instantiates a new Orchestrator
func NewOrchestrator(db *storage.DB, aiClient aiv1connect.AiServiceClient, proxyPort int) *Orchestrator {
	return &Orchestrator{
		db:            db,
		aiClient:      aiClient,
		browserClient: browser.NewClient(""),
		proxyPort:     proxyPort,
		verification:  NewVerificationEngine(aiClient),
	}
}

// Start spawns a background goroutine to execute the scan sequence
func (o *Orchestrator) Start(scanID string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		defer func() {
			// Global browser context cleanup when scan finishes or fails
			endReq, _ := http.NewRequest("POST", "http://127.0.0.1:3010/end-session", strings.NewReader(fmt.Sprintf(`{"scanId":"%s"}`, scanID)))
			if endReq != nil {
				endReq.Header.Set("Content-Type", "application/json")
				_, _ = http.DefaultClient.Do(endReq)
			}
		}()

		log.Printf("[Orchestrator] Launching background scan execution for Scan ID: %s", scanID)

		var targetURL string
		var profileInt int
		err := o.db.QueryRowContext(ctx, "SELECT target_url, profile FROM scans WHERE id = ?", scanID).Scan(&targetURL, &profileInt)
		if err != nil {
			log.Printf("[Orchestrator] [ERROR] Failed to load scan %s: %v", scanID, err)
			o.updateScanStatus(scanID, scanv1.ScanStatus_SCAN_STATUS_FAILED, 0.0)
			return
		}

		profile := scanv1.ScanProfile(profileInt)
		o.profile = profile
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

		as := scanner.NewActiveScanner(o.db, scanID, o.proxyPort)

		var prepModules []string
		var parallelModules []string
		var completionModules []string

		for _, m := range modules {
			switch m {
			case ModuleRecon, ModuleAuthDiscovery, ModuleCrawlStatic, ModulePassive:
				prepModules = append(prepModules, m)
			case ModuleHeaders, ModuleCors, ModuleXssReflected, ModuleSqliBasic, ModuleCsrfBasic, ModuleRateLimitBasic, ModuleNuclei, ModulePathTraversal:
				parallelModules = append(parallelModules, m)
			case ModuleVisualExploit, ModuleReport:
				completionModules = append(completionModules, m)
			default:
				prepModules = append(prepModules, m)
			}
		}

		// 1. Preparation Phase (Sequential)
		for _, module := range prepModules {
			select {
			case <-ctx.Done():
				log.Printf("[Orchestrator] Scan %s timed out during prep. Proceeding to final report.", scanID)
				goto finalize
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
						select {
						case <-ctx.Done():
							return
						default:
							startedAt := startParallelModule(m)
							err := o.runModule(ctx, scanID, targetURL, m, as)
							updateParallelProgress(m, startedAt, err)
						}
					}
				}()
			}
			// Wait for parallel modules with a "max-wait" safety buffer
			waitDone := make(chan struct{})
			go func() {
				wg.Wait()
				close(waitDone)
			}()

			select {
			case <-waitDone:
				log.Printf("[Orchestrator] All parallel modules finished.")
			case <-time.After(10 * time.Minute):
				log.Printf("[Orchestrator] [WARNING] Parallel modules timed out after 10m safety buffer. Forcing finalization.")
			}
		}

	finalize:
		// 3. Completion Phase (Sequential)
		for _, module := range completionModules {
			// Even if context is cancelled, we try to run completion modules (like Report) with a fresh, short-lived context.
			reportCtx, reportCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			
			phaseName := moduleDisplayName(module)
			o.publishPhaseStart(scanID, phaseName)
			startedAt := time.Now()
			_ = o.db.UpsertScanModule(reportCtx, scanID, phaseName, storage.ModuleRunning, &startedAt, nil, "")

			err := o.runModule(reportCtx, scanID, targetURL, module, as)
			completedAt := time.Now()
			if err != nil {
				o.publishModuleError(scanID, phaseName, err)
				log.Printf("[Orchestrator] [WARNING] Completion Module %s failed: %v", module, err)
				_ = o.db.UpsertScanModule(reportCtx, scanID, phaseName, storage.ModuleFailed, &startedAt, &completedAt, err.Error())
			} else {
				_ = o.db.UpsertScanModule(reportCtx, scanID, phaseName, storage.ModuleSuccess, &startedAt, &completedAt, "")
			}
			reportCancel()

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

		// --- SCAN COMPLETION METRICS ---
		o.logScanMetrics(ctx, scanID)

		GlobalBroker.Publish(Event{
			ScanID:    scanID,
			Type:      EventScanCompleted,
			Timestamp: time.Now(),
		})
	}()
}


// logScanMetrics logs a summary of key metrics at scan completion.
// Expected after Phase 1 & 2: gemini_calls = 0 during scan execution.
func (o *Orchestrator) logScanMetrics(ctx context.Context, scanID string) {
	var formsDiscovered, endpointCount, findingsCount int
	var geminiCalls int

	_ = o.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM forms WHERE scan_id = ?", scanID).Scan(&formsDiscovered)
	_ = o.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM endpoints WHERE scan_id = ?", scanID).Scan(&endpointCount)
	_ = o.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE scan_id = ? AND is_false_positive = 0", scanID).Scan(&findingsCount)
	_ = o.db.QueryRowContext(ctx, "SELECT COALESCE(gemini_calls, 0) FROM scans WHERE id = ?", scanID).Scan(&geminiCalls)

	metrics, _ := o.db.GetAttackMetrics(ctx, scanID)
	attackAttempts := 0
	attackVerified := 0
	if metrics != nil {
		attackAttempts = metrics.AttacksExecuted
		attackVerified = metrics.AttacksVerified
	}

	log.Printf(
		"[Orchestrator] [METRICS] Scan %s | forms=%d endpoints=%d attack_attempts=%d attack_verifications=%d findings=%d gemini_calls=%d",
		scanID, formsDiscovered, endpointCount, attackAttempts, attackVerified, findingsCount, geminiCalls,
	)

	if geminiCalls > 0 {
		log.Printf("[Orchestrator] [METRICS] [WARNING] gemini_calls=%d during scan — AI was invoked during scan execution. Expected 0.", geminiCalls)
	} else {
		log.Printf("[Orchestrator] [METRICS] [OK] gemini_calls=0 — scan executed with zero AI calls.")
	}
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

func (o *Orchestrator) publishBrowserScreenshot(scanID string, screenshotB64 string) {
	if screenshotB64 == "" {
		return
	}
	imgData := screenshotB64
	if !strings.HasPrefix(imgData, "data:") {
		imgData = "data:image/png;base64," + imgData
	}
	structVal, _ := structpb.NewStruct(map[string]interface{}{
		"image": imgData,
	})
	GlobalBroker.Publish(Event{
		ScanID:    scanID,
		Type:      "browser.screenshot",
		Timestamp: time.Now(),
		Data:      structVal.AsMap(),
	})
}

func (o *Orchestrator) publishAgentLog(scanID, msg string) {
	GlobalBroker.Publish(Event{
		ScanID:    scanID,
		Type:      EventLogInfo,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"message": msg,
		},
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
	case ModuleAuthDiscovery:
		return "Autonomous Auth Discovery"
	case ModuleReport:
		return "Report Generation"
	case ModuleVisualExploit:
		return "Visual Exploitation"
	default:
		return module
	}
}

func (o *Orchestrator) getAttackSurfaces(ctx context.Context, scanID string, targetURL string) ([]scanner.AttackSurface, error) {
	var surfaces []scanner.AttackSurface

	// 1. Fetch static/recon endpoints
	endpoints, err := o.db.ListEndpoints(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}

	for _, ep := range endpoints {
		if !crawler.IsInCrawlScope(ep.URL, targetURL) {
			continue
		}
		points, _ := scanner.ExtractInsertionPoints(ep.Method, ep.URL, nil, "")
		for _, pt := range points {
			surfaces = append(surfaces, scanner.AttackSurface{
				URL:         ep.URL,
				Method:      ep.Method,
				ContentType: "application/x-www-form-urlencoded",
				Point:       pt,
				IsForm:      false,
			})
		}
	}

	// 2. Fetch discovered forms
	forms, err := o.db.ListForms(ctx, scanID)
	if err != nil {
		log.Printf("[Orchestrator] ListForms error: %v", err)
		return surfaces, nil
	}

	for _, f := range forms {
		if !crawler.IsInCrawlScope(f.URL, targetURL) {
			continue
		}
		var inputs []browser.BrowserElement
		if err := json.Unmarshal([]byte(f.InputsJSON), &inputs); err != nil {
			continue
		}

		for _, in := range inputs {
			tLower := strings.ToLower(in.Type)
			if tLower == "submit" || tLower == "button" || tLower == "image" {
				continue
			}

			paramName := in.Name
			if paramName == "" {
				paramName = in.ID
			}
			if paramName == "" {
				paramName = in.Selector
			}
			if paramName == "" {
				continue
			}

			paramType := scanner.ParamQuery
			if strings.ToUpper(f.Method) == "POST" {
				paramType = scanner.ParamForm
			}

			pt := scanner.InsertionPoint{
				Name:  paramName,
				Type:  paramType,
				Value: in.Value,
			}

			var baseBody []byte
			if strings.ToUpper(f.Method) == "POST" {
				baseBody = o.buildFormBody(f.InputsJSON)
			}

			formActionURL := o.resolveActionURL(f.URL, f.Action)

			if !crawler.IsInCrawlScope(formActionURL, targetURL) {
				continue
			}

			surfaces = append(surfaces, scanner.AttackSurface{
				URL:         formActionURL,
				Method:      f.Method,
				BaseBody:    baseBody,
				ContentType: "application/x-www-form-urlencoded",
				Point:       pt,
				IsForm:      true,
				FormSel:     f.Selector,
				FormPageURL: f.URL,
			})
		}
	}

	return surfaces, nil
}

func (o *Orchestrator) buildFormBody(inputsJSON string) []byte {
	var inputs []browser.BrowserElement
	if err := json.Unmarshal([]byte(inputsJSON), &inputs); err != nil {
		return nil
	}
	vals := url.Values{}
	for _, in := range inputs {
		tLower := strings.ToLower(in.Type)
		if tLower != "submit" && tLower != "button" && tLower != "image" {
			name := in.Name
			if name == "" {
				name = in.ID
			}
			if name != "" {
				vals.Set(name, in.Value)
			}
		}
	}
	return []byte(vals.Encode())
}

func (o *Orchestrator) resolveActionURL(baseURL, action string) string {
	if action == "" {
		return baseURL
	}
	if strings.HasPrefix(action, "http://") || strings.HasPrefix(action, "https://") {
		return action
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return action
	}
	ref, err := url.Parse(action)
	if err != nil {
		return action
	}
	return base.ResolveReference(ref).String()
}

func makeFormSubmitScript(actionURL, method string, body []byte) string {
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return fmt.Sprintf(`
			fetch("%s", {
				method: "%s",
				body: %q
			}).then(r => r.text()).then(html => {
				document.open();
				document.write(html);
				document.close();
			});
		`, actionURL, method, string(body))
	}

	js := fmt.Sprintf(`
		(function() {
			const form = document.createElement('form');
			form.method = %q;
			form.action = %q;
	`, method, actionURL)

	for k, vs := range vals {
		for _, v := range vs {
			js += fmt.Sprintf(`
				{
					const inp = document.createElement('input');
					inp.type = 'hidden';
					inp.name = %q;
					inp.value = %q;
					form.appendChild(inp);
				}
			`, k, v)
		}
	}

	js += `
			document.body.appendChild(form);
			form.submit();
		})();
	`
	return js
}

func (o *Orchestrator) executeDeterministicAttack(
	ctx context.Context,
	scanID string,
	workerID string,
	method string,
	urlStr string,
	body []byte,
	formPageURL string,
) (*browser.ActionResult, error) {
	methodUpper := strings.ToUpper(method)
	if methodUpper == "GET" || len(body) == 0 {
		actionReq := browser.ActionRequest{
			ScanID:    scanID,
			WorkerID:  workerID,
			URL:       urlStr,
			Action:    "navigate",
			ProxyPort: o.proxyPort,
		}
		res, err := o.browserClient.ExecuteAction(ctx, actionReq)
		if err == nil && res != nil && res.ScreenshotBase64 != "" {
			o.publishBrowserScreenshot(scanID, res.ScreenshotBase64)
		}
		return res, err
	}

	navigateURL := urlStr
	if formPageURL != "" {
		navigateURL = formPageURL
	}

	navRes, _ := o.browserClient.ExecuteAction(ctx, browser.ActionRequest{
		ScanID:    scanID,
		WorkerID:  workerID,
		URL:       navigateURL,
		Action:    "navigate",
		ProxyPort: o.proxyPort,
	})
	if navRes != nil && navRes.ScreenshotBase64 != "" {
		o.publishBrowserScreenshot(scanID, navRes.ScreenshotBase64)
	}

	script := makeFormSubmitScript(urlStr, methodUpper, body)

	actionReq := browser.ActionRequest{
		ScanID:    scanID,
		WorkerID:  workerID,
		Action:    "evaluate",
		Value:     script,
		ProxyPort: o.proxyPort,
	}
	res, err := o.browserClient.ExecuteAction(ctx, actionReq)
	if err == nil && res != nil && res.ScreenshotBase64 != "" {
		o.publishBrowserScreenshot(scanID, res.ScreenshotBase64)
	}
	return res, err
}

func (o *Orchestrator) runAgentSqliAgent(ctx context.Context, scanID, targetURL string, onLog func(string)) error {
	surfaces, err := o.getAttackSurfaces(ctx, scanID, targetURL)
	if err != nil {
		return err
	}

	exec := attack.NewAgentSQLiExecutor(
		o.db,
		o.browserClient,
		o.aiClient,
		scanID,
		o.proxyPort,
		onLog,
		func(b64 string) {
			o.publishBrowserScreenshot(scanID, b64)
		},
	)

	for _, surf := range surfaces {
		err := exec.Execute(ctx, surf)
		if err != nil {
			log.Printf("[Orchestrator] SQLi Agent execution failed on surface %s: %v", surf.URL, err)
		}
	}
	return nil
}

func (o *Orchestrator) runAgentSqli(ctx context.Context, scanID, targetURL string, onLog func(string)) error {
	surfaces, err := o.getAttackSurfaces(ctx, scanID, targetURL)
	if err != nil {
		return err
	}

	for _, surf := range surfaces {
		o.publishAgentLog(scanID, fmt.Sprintf("[AGENT] Target endpoint identified: %s %s (parameter: %s)", surf.Method, surf.URL, surf.Point.Name))
		for _, payload := range scanner.SQLiPayloads {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			o.publishAgentLog(scanID, fmt.Sprintf("[AGENT] Testing SQL Injection payload: %s", payload.Value))
			_ = o.db.IncrementAttackExecuted(ctx, scanID)

			injectedURL, injectedBody := scanner.BuildInjectedRequest(surf.Method, surf.URL, surf.BaseBody, surf.ContentType, surf.Point, payload.Value)

			attemptID, _ := o.db.SaveAttackAttempt(ctx, storage.AttackAttemptInput{
				ScanID:           scanID,
				AttackType:       "SQL Injection",
				Endpoint:         injectedURL,
				Payload:          payload.Value,
				RequestCaptured:  fmt.Sprintf("%s %s\nContent-Type: %s\n\n%s", surf.Method, injectedURL, surf.ContentType, string(injectedBody)),
				ResponseCaptured: "",
				EvidenceFound:    "",
				Result:           "failed",
			})

			actionRes, err := o.executeDeterministicAttack(ctx, scanID, "sqli", surf.Method, injectedURL, injectedBody, surf.FormPageURL)
			if err != nil || actionRes == nil {
				_ = o.db.IncrementAttackFailed(ctx, scanID)
				o.publishAgentLog(scanID, fmt.Sprintf("[AGENT] Browser action failed or timed out during attack."))
				continue
			}

			if attemptID != "" && actionRes.PageSource != "" {
				resExcerpt := actionRes.PageSource
				if len(resExcerpt) > 1000 {
					resExcerpt = resExcerpt[:1000]
				}
				_, _ = o.db.ExecContext(ctx, "UPDATE attack_attempts SET response_captured = ? WHERE id = ?", resExcerpt, attemptID)
			}

			vr := o.verification.VerifySQLi(ctx, injectedURL, payload.Value, actionRes.PageSource, actionRes.ScreenshotBase64)

			if !vr.Verified {
				_ = o.db.IncrementAttackFailed(ctx, scanID)
				o.publishAgentLog(scanID, fmt.Sprintf("[AGENT] Exploit failed: verification returned negative result."))
				continue
			}

			_ = o.db.IncrementAttackVerified(ctx, scanID)
			o.publishAgentLog(scanID, fmt.Sprintf("[AGENT] EXPLOIT SUCCESSFUL! Verified SQL Injection on parameter %s. Evidence: %s", surf.Point.Name, vr.EvidenceSummary))
			_, _ = o.db.ExecContext(ctx, "UPDATE attack_attempts SET result = ?, evidence_found = ? WHERE id = ?", "verified", vr.EvidenceSummary, attemptID)

			findingID, err := o.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
				ScanID:            scanID,
				Title:             fmt.Sprintf("SQL Injection - %s", surf.Point.Name),
				Description:       fmt.Sprintf("[%s] %s\n\nVerification: %s", payload.Strategy, payload.Description, vr.EvidenceSummary),
				Severity:          "HIGH",
				VulnerabilityType: "SQL Injection",
				Endpoint:          injectedURL,
				Payload:           payload.Value,
				ResponseStatus:    200,
				Confidence:        vr.Confidence,
				Category:          storage.StatePotentialFinding,
			}, storage.EvidenceInput{
				FlowID:          0,
				EvidenceType:    storage.EvidenceScreenshot,
				RequestExcerpt:  fmt.Sprintf("%s %s\n\n%s", surf.Method, injectedURL, string(injectedBody)),
				ResponseExcerpt: actionRes.PageSource,
				ScreenshotB64:   actionRes.ScreenshotBase64,
			})

			if err == nil {
				verifID, verifErr := o.db.SaveVerification(ctx, findingID, scanID, vr)
				if verifErr == nil {
					if _, updateErr := o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID); updateErr != nil {
						o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to update finding category: %v", updateErr))
					}
				} else {
					o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save verification: %v", verifErr))
				}
			} else {
				o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save finding: %v", err))
			}
		}
	}

	// 2. Call SQLMap fuzzer loop if tool is available
	if !attack.ToolAvailable("sqlmap") {
		o.publishAgentLog(scanID, "[Orchestrator] [WARNING] SQLMap fuzzer not found in PATH. Downgrading gracefully to internal SQLi fuzzer.")
	} else {
		o.publishAgentLog(scanID, "[Orchestrator] [SQLi] SQLMap is available. Fuzzing discovered endpoints...")
		cookieStr := o.getAuthCookieString(ctx, scanID)
		endpoints, err := o.db.ListEndpoints(ctx, scanID)
		if err == nil {
			var fuzzedAny bool
			for _, ep := range endpoints {
				if strings.Contains(ep.URL, "?") {
					o.publishAgentLog(scanID, fmt.Sprintf("[Orchestrator] [SQLi] Running SQLMap on parameter endpoint: %s", ep.URL))
					sqliFindings, err := attack.RunSQLMapScan(ctx, ep.URL, o.proxyPort, cookieStr, onLog)
					if err == nil && len(sqliFindings) > 0 {
						fuzzedAny = true
						for _, f := range sqliFindings {
							_ = o.db.IncrementAttackExecuted(ctx, scanID)
							_ = o.db.IncrementAttackVerified(ctx, scanID)
							findingID, err := o.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
								ScanID:            scanID,
								Title:             f.Title,
								Description:       fmt.Sprintf("%s\n\nVerification: Verified by SQLMap fuzzer.", f.Evidence),
								Severity:          f.Severity,
								VulnerabilityType: f.VulnerabilityType,
								Endpoint:          f.Endpoint,
								Payload:           f.Payload,
								ResponseStatus:    200,
								Confidence:        0.95,
								Category:          storage.StatePotentialFinding,
							}, storage.EvidenceInput{
								FlowID:          0,
								EvidenceType:    storage.EvidenceDOM,
								RequestExcerpt:  fmt.Sprintf("SQLMap vulnerability scan: %s", f.Endpoint),
								ResponseExcerpt: f.Evidence,
							})
							if err == nil {
								vr := &storage.VerificationResult{
									EndpointURL:     f.Endpoint,
									Payload:         f.Payload,
									VerifiedAt:      time.Now(),
									Verified:        true,
									Confidence:      0.95,
									Method:          storage.VerificationDOMMarker,
									EvidenceSummary: fmt.Sprintf("SQLMap verified vulnerability details: %s", f.Evidence),
								}
								verifID, verifErr := o.db.SaveVerification(ctx, findingID, scanID, vr)
								if verifErr == nil {
									if _, updateErr := o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID); updateErr != nil {
										o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to update finding category: %v", updateErr))
									}
								} else {
									o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save verification: %v", verifErr))
								}
							} else {
								o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save finding: %v", err))
							}
						}
					}
				}
			}
			// Fallback to seed target URL if no parameter-based endpoints were found
			if !fuzzedAny {
				o.publishAgentLog(scanID, fmt.Sprintf("[Orchestrator] [SQLi] Running SQLMap on seed URL: %s", targetURL))
				sqliFindings, err := attack.RunSQLMapScan(ctx, targetURL, o.proxyPort, cookieStr, onLog)

				if err == nil {
					for _, f := range sqliFindings {
						_ = o.db.IncrementAttackExecuted(ctx, scanID)
						_ = o.db.IncrementAttackVerified(ctx, scanID)
						findingID, err := o.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
							ScanID:            scanID,
							Title:             f.Title,
							Description:       fmt.Sprintf("%s\n\nVerification: Verified by SQLMap fuzzer.", f.Evidence),
							Severity:          f.Severity,
							VulnerabilityType: f.VulnerabilityType,
							Endpoint:          f.Endpoint,
							Payload:           f.Payload,
							ResponseStatus:    200,
							Confidence:        0.95,
							Category:          storage.StatePotentialFinding,
						}, storage.EvidenceInput{
							FlowID:          0,
							EvidenceType:    storage.EvidenceDOM,
							RequestExcerpt:  fmt.Sprintf("SQLMap vulnerability scan: %s", f.Endpoint),
							ResponseExcerpt: f.Evidence,
						})
						if err == nil {
							vr := &storage.VerificationResult{
								EndpointURL:     f.Endpoint,
								Payload:         f.Payload,
								VerifiedAt:      time.Now(),
								Verified:        true,
								Confidence:      0.95,
								Method:          storage.VerificationDOMMarker,
								EvidenceSummary: fmt.Sprintf("SQLMap verified vulnerability details: %s", f.Evidence),
							}
							verifID, verifErr := o.db.SaveVerification(ctx, findingID, scanID, vr)
							if verifErr == nil {
								if _, updateErr := o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID); updateErr != nil {
									o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to update finding category: %v", updateErr))
								}
							} else {
								o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save verification: %v", verifErr))
							}
						} else {
							o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save finding: %v", err))
						}
					}
				}
			}
		}
	}

	return nil
}


func (o *Orchestrator) runAgentXss(ctx context.Context, scanID, targetURL string, onLog func(string)) error {
	surfaces, err := o.getAttackSurfaces(ctx, scanID, targetURL)
	if err != nil {
		return err
	}

	for _, surf := range surfaces {
		o.publishAgentLog(scanID, fmt.Sprintf("[AGENT] Target endpoint identified: %s %s (parameter: %s)", surf.Method, surf.URL, surf.Point.Name))
		for _, payload := range scanner.XSSPayloads {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			o.publishAgentLog(scanID, fmt.Sprintf("[AGENT] Testing XSS payload: %s", payload.Value))
			_ = o.db.IncrementAttackExecuted(ctx, scanID)

			injectedURL, injectedBody := scanner.BuildInjectedRequest(surf.Method, surf.URL, surf.BaseBody, surf.ContentType, surf.Point, payload.Value)

			attemptID, _ := o.db.SaveAttackAttempt(ctx, storage.AttackAttemptInput{
				ScanID:           scanID,
				AttackType:       "XSS",
				Endpoint:         injectedURL,
				Payload:          payload.Value,
				RequestCaptured:  fmt.Sprintf("%s %s\nContent-Type: %s\n\n%s", surf.Method, injectedURL, surf.ContentType, string(injectedBody)),
				ResponseCaptured: "",
				EvidenceFound:    "",
				Result:           "failed",
			})

			actionRes, err := o.executeDeterministicAttack(ctx, scanID, "xss", surf.Method, injectedURL, injectedBody, surf.FormPageURL)
			if err != nil || actionRes == nil {
				_ = o.db.IncrementAttackFailed(ctx, scanID)
				o.publishAgentLog(scanID, fmt.Sprintf("[AGENT] Browser action failed or timed out during attack."))
				continue
			}

			if attemptID != "" && actionRes.PageSource != "" {
				resExcerpt := actionRes.PageSource
				if len(resExcerpt) > 1000 {
					resExcerpt = resExcerpt[:1000]
				}
				_, _ = o.db.ExecContext(ctx, "UPDATE attack_attempts SET response_captured = ? WHERE id = ?", resExcerpt, attemptID)
			}

			vr := o.verification.VerifyXSS(ctx, "Reflected XSS", injectedURL, payload.Value, actionRes.PageSource, actionRes.ScreenshotBase64)

			if !vr.Verified {
				_ = o.db.IncrementAttackFailed(ctx, scanID)
				o.publishAgentLog(scanID, fmt.Sprintf("[AGENT] Exploit failed: verification returned negative result."))
				continue
			}

			_ = o.db.IncrementAttackVerified(ctx, scanID)
			o.publishAgentLog(scanID, fmt.Sprintf("[AGENT] EXPLOIT SUCCESSFUL! Verified Reflected XSS on parameter %s. Evidence: %s", surf.Point.Name, vr.EvidenceSummary))
			_, _ = o.db.ExecContext(ctx, "UPDATE attack_attempts SET result = ?, evidence_found = ? WHERE id = ?", "verified", vr.EvidenceSummary, attemptID)

			findingID, err := o.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
				ScanID:            scanID,
				Title:             fmt.Sprintf("XSS - %s", surf.Point.Name),
				Description:       fmt.Sprintf("%s\n\nVerification: %s", payload.Description, vr.EvidenceSummary),
				Severity:          "HIGH",
				VulnerabilityType: "XSS",
				Endpoint:          injectedURL,
				Payload:           payload.Value,
				ResponseStatus:    200,
				Confidence:        vr.Confidence,
				Category:          storage.StatePotentialFinding,
			}, storage.EvidenceInput{
				FlowID:          0,
				EvidenceType:    storage.EvidenceScreenshot,
				RequestExcerpt:  fmt.Sprintf("%s %s\n\n%s", surf.Method, injectedURL, string(injectedBody)),
				ResponseExcerpt: actionRes.PageSource,
				ScreenshotB64:   actionRes.ScreenshotBase64,
			})

			if err == nil {
				verifID, verifErr := o.db.SaveVerification(ctx, findingID, scanID, vr)
				if verifErr == nil {
					if _, updateErr := o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID); updateErr != nil {
						o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to update finding category: %v", updateErr))
					}
				} else {
					o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save verification: %v", verifErr))
				}
			} else {
				o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save finding: %v", err))
			}
		}
	}

	// 2. Call Dalfox XSS fuzzer loop if tool is available
	if !attack.ToolAvailable("dalfox") {
		o.publishAgentLog(scanID, "[Orchestrator] [WARNING] Dalfox fuzzer not found in PATH. Downgrading gracefully to internal XSS fuzzer.")
	} else {
		o.publishAgentLog(scanID, "[Orchestrator] [XSS] Dalfox is available. Fuzzing discovered endpoints...")
		cookieStr := o.getAuthCookieString(ctx, scanID)
		endpoints, err := o.db.ListEndpoints(ctx, scanID)
		if err == nil {
			var fuzzedAny bool
			for _, ep := range endpoints {
				if strings.Contains(ep.URL, "?") {
					o.publishAgentLog(scanID, fmt.Sprintf("[Orchestrator] [XSS] Running Dalfox on parameter endpoint: %s", ep.URL))
					dfFindings, err := attack.RunDalfoxScan(ctx, ep.URL, o.proxyPort, cookieStr, onLog)
					if err == nil && len(dfFindings) > 0 {
						fuzzedAny = true
						for _, f := range dfFindings {
							_ = o.db.IncrementAttackExecuted(ctx, scanID)
							_ = o.db.IncrementAttackVerified(ctx, scanID)
							findingID, err := o.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
								ScanID:            scanID,
								Title:             f.Title,
								Description:       fmt.Sprintf("%s\n\nVerification: Verified by Dalfox fuzzer.", f.Evidence),
								Severity:          f.Severity,
								VulnerabilityType: f.VulnerabilityType,
								Endpoint:          f.Endpoint,
								Payload:           f.Payload,
								ResponseStatus:    200,
								Confidence:        0.95,
								Category:          storage.StatePotentialFinding,
							}, storage.EvidenceInput{
								FlowID:          0,
								EvidenceType:    storage.EvidenceDOM,
								RequestExcerpt:  fmt.Sprintf("Dalfox vulnerability scan: %s", f.Endpoint),
								ResponseExcerpt: f.Evidence,
							})
							if err == nil {
								vr := &storage.VerificationResult{
									EndpointURL:     f.Endpoint,
									Payload:         f.Payload,
									VerifiedAt:      time.Now(),
									Verified:        true,
									Confidence:      0.95,
									Method:          storage.VerificationDOMMarker,
									EvidenceSummary: fmt.Sprintf("Dalfox verified vulnerability details: %s", f.Evidence),
								}
								verifID, verifErr := o.db.SaveVerification(ctx, findingID, scanID, vr)
								if verifErr == nil {
									if _, updateErr := o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID); updateErr != nil {
										o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to update finding category: %v", updateErr))
									}
								} else {
									o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save verification: %v", verifErr))
								}
							} else {
								o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save finding: %v", err))
							}
						}
					}
				}
			}
			// Fallback to seed target URL if no parameter-based endpoints were found
			if !fuzzedAny {
				o.publishAgentLog(scanID, fmt.Sprintf("[Orchestrator] [XSS] Running Dalfox on seed URL: %s", targetURL))
				dfFindings, err := attack.RunDalfoxScan(ctx, targetURL, o.proxyPort, cookieStr, onLog)
				if err == nil {
					for _, f := range dfFindings {
						_ = o.db.IncrementAttackExecuted(ctx, scanID)
						_ = o.db.IncrementAttackVerified(ctx, scanID)
						findingID, err := o.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
							ScanID:            scanID,
							Title:             f.Title,
							Description:       fmt.Sprintf("%s\n\nVerification: Verified by Dalfox fuzzer.", f.Evidence),
							Severity:          f.Severity,
							VulnerabilityType: f.VulnerabilityType,
							Endpoint:          f.Endpoint,
							Payload:           f.Payload,
							ResponseStatus:    200,
							Confidence:        0.95,
							Category:          storage.StatePotentialFinding,
						}, storage.EvidenceInput{
							FlowID:          0,
							EvidenceType:    storage.EvidenceDOM,
							RequestExcerpt:  fmt.Sprintf("Dalfox vulnerability scan: %s", f.Endpoint),
							ResponseExcerpt: f.Evidence,
						})
						if err == nil {
							vr := &storage.VerificationResult{
								EndpointURL:     f.Endpoint,
								Payload:         f.Payload,
								VerifiedAt:      time.Now(),
								Verified:        true,
								Confidence:      0.95,
								Method:          storage.VerificationDOMMarker,
								EvidenceSummary: fmt.Sprintf("Dalfox verified vulnerability details: %s", f.Evidence),
							}
							verifID, verifErr := o.db.SaveVerification(ctx, findingID, scanID, vr)
							if verifErr == nil {
								if _, updateErr := o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID); updateErr != nil {
									o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to update finding category: %v", updateErr))
								}
							} else {
								o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save verification: %v", verifErr))
							}
						} else {
							o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save finding: %v", err))
						}
					}
				}
			}
		}
	}

	return nil
}




func (o *Orchestrator) runAgentPathTraversal(ctx context.Context, scanID, targetURL string) error {
	surfaces, err := o.getAttackSurfaces(ctx, scanID, targetURL)
	if err != nil {
		return err
	}

	for _, surf := range surfaces {
		pLower := strings.ToLower(surf.Point.Name)
		if !strings.Contains(pLower, "file") && !strings.Contains(pLower, "path") &&
			!strings.Contains(pLower, "doc") && !strings.Contains(pLower, "page") &&
			!strings.Contains(pLower, "url") {
			continue
		}

		for _, payload := range scanner.PathTraversalPayloads {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			injectedURL, injectedBody := scanner.BuildInjectedRequest(surf.Method, surf.URL, surf.BaseBody, surf.ContentType, surf.Point, payload.Value)

			_ = o.db.IncrementAttackExecuted(ctx, scanID)

			attemptID, _ := o.db.SaveAttackAttempt(ctx, storage.AttackAttemptInput{
				ScanID:           scanID,
				AttackType:       "Path Traversal",
				Endpoint:         injectedURL,
				Payload:          payload.Value,
				RequestCaptured:  fmt.Sprintf("%s %s\nContent-Type: %s\n\n%s", surf.Method, injectedURL, surf.ContentType, string(injectedBody)),
				ResponseCaptured: "",
				EvidenceFound:    "",
				Result:           "failed",
			})

			actionRes, err := o.executeDeterministicAttack(ctx, scanID, "pathtraversal", surf.Method, injectedURL, injectedBody, surf.FormPageURL)
			if err != nil || actionRes == nil {
				_ = o.db.IncrementAttackFailed(ctx, scanID)
				continue
			}

			if attemptID != "" && actionRes.PageSource != "" {
				resExcerpt := actionRes.PageSource
				if len(resExcerpt) > 1000 {
					resExcerpt = resExcerpt[:1000]
				}
				_, _ = o.db.ExecContext(ctx, "UPDATE attack_attempts SET response_captured = ? WHERE id = ?", resExcerpt, attemptID)
			}

			vr := o.verification.VerifyPathTraversal(ctx, injectedURL, payload.Value, actionRes.PageSource, actionRes.ScreenshotBase64)

			if !vr.Verified {
				_ = o.db.IncrementAttackFailed(ctx, scanID)
				continue
			}

			_ = o.db.IncrementAttackVerified(ctx, scanID)
			_, _ = o.db.ExecContext(ctx, "UPDATE attack_attempts SET result = ?, evidence_found = ? WHERE id = ?", "verified", vr.EvidenceSummary, attemptID)

			findingID, err := o.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
				ScanID:            scanID,
				Title:             fmt.Sprintf("Path Traversal - %s", surf.Point.Name),
				Description:       payload.Description + "\n\nVerification: " + vr.EvidenceSummary,
				Severity:          "HIGH",
				VulnerabilityType: "Path Traversal",
				Endpoint:          injectedURL,
				Payload:           payload.Value,
				ResponseStatus:    200,
				Confidence:        vr.Confidence,
				Category:          storage.StatePotentialFinding,
			}, storage.EvidenceInput{
				FlowID:          0,
				EvidenceType:    storage.EvidenceScreenshot,
				RequestExcerpt:  fmt.Sprintf("%s %s\n\n%s", surf.Method, injectedURL, string(injectedBody)),
				ResponseExcerpt: actionRes.PageSource,
				ScreenshotB64:   actionRes.ScreenshotBase64,
			})

			if err == nil {
				verifID, verifErr := o.db.SaveVerification(ctx, findingID, scanID, vr)
				if verifErr == nil {
					if _, updateErr := o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID); updateErr != nil {
						o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to update finding category: %v", updateErr))
					}
				} else {
					o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save verification: %v", verifErr))
				}
			} else {
				o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save finding: %v", err))
			}
		}
	}
	return nil
}

func (o *Orchestrator) runAgentCsrf(ctx context.Context, scanID, targetURL string) error {
	forms, err := o.db.ListForms(ctx, scanID)
	if err != nil {
		return err
	}

	for _, f := range forms {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		method := strings.ToUpper(f.Method)
		if method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" {
			continue
		}

		if !crawler.IsInCrawlScope(f.URL, targetURL) {
			continue
		}

		// Construct body from inputs
		body := o.buildFormBody(f.InputsJSON)
		contentType := "application/x-www-form-urlencoded"

		urlStr := o.resolveActionURL(f.URL, f.Action)

		reqHeaders := make(http.Header)
		reqHeaders.Set("Content-Type", contentType)

		// 1. Heuristically check if this POST/PUT request might lack CSRF tokens
		res, err := scanner.DetectCSRFHeuristic(method, urlStr, reqHeaders, body, contentType)
		if err != nil || res == nil || !res.Suspected {
			continue
		}

		// 2. Execute Attack (deterministic browser execution)
		_ = o.db.IncrementAttackExecuted(ctx, scanID)

		attemptID, _ := o.db.SaveAttackAttempt(ctx, storage.AttackAttemptInput{
			ScanID:           scanID,
			AttackType:       "CSRF",
			Endpoint:         urlStr,
			Payload:          string(body),
			RequestCaptured:  fmt.Sprintf("%s %s\nContent-Type: %s\n\n%s", method, urlStr, contentType, string(body)),
			ResponseCaptured: "",
			EvidenceFound:    "",
			Result:           "failed",
		})

		actionRes, err := o.executeDeterministicAttack(ctx, scanID, "csrf", method, urlStr, body, "")
		if err != nil || actionRes == nil {
			_ = o.db.IncrementAttackFailed(ctx, scanID)
			continue
		}

		if attemptID != "" && actionRes.PageSource != "" {
			resExcerpt := actionRes.PageSource
			if len(resExcerpt) > 1000 {
				resExcerpt = resExcerpt[:1000]
			}
			_, _ = o.db.ExecContext(ctx, "UPDATE attack_attempts SET response_captured = ? WHERE id = ?", resExcerpt, attemptID)
		}

		// 3. Run Verification Engine
		vr := o.verification.VerifyCSRF(ctx, urlStr, string(body), actionRes.PageSource, actionRes.ScreenshotBase64)

		if !vr.Verified {
			_ = o.db.IncrementAttackFailed(ctx, scanID)
			continue
		}

		_ = o.db.IncrementAttackVerified(ctx, scanID)
		_, _ = o.db.ExecContext(ctx, "UPDATE attack_attempts SET result = ?, evidence_found = ? WHERE id = ?", "verified", vr.EvidenceSummary, attemptID)

		// 4. Save finding
		findingID, err := o.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            scanID,
			Title:             fmt.Sprintf("CSRF - %s", urlStr),
			Description:       res.Reason + "\n\nVerification: " + vr.EvidenceSummary,
			Severity:          "HIGH",
			VulnerabilityType: "CSRF",
			Endpoint:          urlStr,
			Payload:           string(body),
			ResponseStatus:    200,
			Confidence:        vr.Confidence,
			Category:          storage.StatePotentialFinding,
		}, storage.EvidenceInput{
			FlowID:          0,
			EvidenceType:    storage.EvidenceScreenshot,
			RequestExcerpt:  fmt.Sprintf("%s %s\n\n%s", method, urlStr, string(body)),
			ResponseExcerpt: actionRes.PageSource,
			ScreenshotB64:   actionRes.ScreenshotBase64,
		})

		if err == nil {
			verifID, verifErr := o.db.SaveVerification(ctx, findingID, scanID, vr)
			if verifErr == nil {
				if _, updateErr := o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID); updateErr != nil {
					o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to update finding category: %v", updateErr))
				}
			} else {
				o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save verification: %v", verifErr))
			}
		} else {
			o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save finding: %v", err))
		}
	}
	return nil
}

func (o *Orchestrator) decideDeterministicAuthAction(
	ctx context.Context,
	scanID string,
	actionRes *browser.ActionResult,
	targetURL string,
	history []*storage.JournalEntry,
) (action string, selector string, value string, reason string, finish bool, needsReview bool) {

	currentURLStr := actionRes.CurrentURL
	pageSourceLower := strings.ToLower(actionRes.PageSource)

	// 0. Check for "Logged In" indicators to terminate early if successful
	hasPasswordInput := false
	for _, f := range actionRes.Forms {
		for _, in := range f.Inputs {
			if strings.ToLower(in.Type) == "password" {
				hasPasswordInput = true
				break
			}
		}
	}
	if strings.Contains(pageSourceLower, `type="password"`) || strings.Contains(pageSourceLower, `type='password'`) || strings.Contains(pageSourceLower, `type=password`) {
		hasPasswordInput = true
	}

	if !hasPasswordInput {
		urlLower := strings.ToLower(currentURLStr)
		isDashboardURL := strings.Contains(urlLower, "/dashboard") || strings.Contains(urlLower, "/admin") || strings.Contains(urlLower, "/panel") || strings.Contains(urlLower, "/home")

		loggedInIndicators := []string{
			"sign off", "signout", "sign-out", "log out", "logout",
			"my account", "user profile", "edit profile",
			"administrative tools", "global settings",
		}

		isLoggedIn := false
		matchedIndicator := ""

		if isDashboardURL {
			isLoggedIn = true
			matchedIndicator = "dashboard/admin URL path"
		} else {
			for _, indicator := range loggedInIndicators {
				if strings.Contains(pageSourceLower, indicator) {
					isLoggedIn = true
					matchedIndicator = indicator
					break
				}
			}
		}

		// Also check "welcome" if it's not a landing page with login links
		if !isLoggedIn && (strings.Contains(pageSourceLower, "welcome") || strings.Contains(pageSourceLower, "hello")) {
			hasLoginLink := false
			for _, l := range actionRes.Links {
				lText := strings.ToLower(l.Text)
				lHref := strings.ToLower(l.Href)
				if strings.Contains(lText, "login") || strings.Contains(lText, "sign in") || strings.Contains(lText, "log in") ||
					strings.Contains(lHref, "login") || strings.Contains(lHref, "signin") {
					hasLoginLink = true
					break
				}
			}
			if !hasLoginLink {
				isLoggedIn = true
				matchedIndicator = "welcome message (no login links)"
			}
		}

		if isLoggedIn {
			reason = fmt.Sprintf("Authenticated state detected (indicator: '%s').", matchedIndicator)

			// Save a finding to mark successful authentication
			findingID, err := o.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
				ScanID:            scanID,
				Title:             "Successful Authentication",
				Description:       fmt.Sprintf("LastResort successfully bypassed or discovered authentication credentials. Indicator found: '%s'.", matchedIndicator),
				Severity:          "INFO",
				VulnerabilityType: "Authentication",
				Endpoint:          currentURLStr,
				Category:          storage.StatePotentialFinding,
				Confidence:        1.0,
			}, storage.EvidenceInput{
				FlowID:          0,
				EvidenceType:    storage.EvidenceDOM,
				RequestExcerpt:  "Auth Discovery Phase",
				ResponseExcerpt: matchedIndicator,
			})

			if err == nil {
				vr := &storage.VerificationResult{
					EndpointURL:     currentURLStr,
					Payload:         "Auth Discovery Phase",
					VerifiedAt:      time.Now(),
					Verified:        true,
					Confidence:      1.0,
					Method:          storage.VerificationDOMMarker,
					EvidenceSummary: fmt.Sprintf("Authentication succeeded. Indicator found: '%s'.", matchedIndicator),
				}
				verifID, verifErr := o.db.SaveVerification(ctx, findingID, scanID, vr)
				if verifErr == nil {
					if _, updateErr := o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID); updateErr != nil {
						o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to update finding category: %v", updateErr))
					}
				} else {
					o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save verification: %v", verifErr))
				}
			} else {
				o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save finding: %v", err))
			}

			return "finish", "", "", reason, true, false
		}
	}

	// Helper to check if we already tried a selector (allowing max 2 retries, i.e. 3 total attempts)
	hasTried := func(act, sel, val string) bool {
		totalAttempts := 0
		for _, h := range history {
			if h.Action == act && h.Selector == sel && (val == "" || h.Value == val) {
				totalAttempts++
			}
		}
		if totalAttempts >= 3 {
			return true
		}

		// If the input already contains the target value, consider it tried (no need to refill)
		if act == "fill" {
			if actionRes != nil {
				for _, f := range actionRes.Forms {
					for _, in := range f.Inputs {
						if in.Selector == sel && in.Value == val {
							return true
						}
					}
				}
			}
			// Also check if we already filled this selector after the last click in history
			lastClickIdx := -1
			for i := len(history) - 1; i >= 0; i-- {
				if history[i].Action == "click" {
					lastClickIdx = i
					break
				}
			}
			for i := lastClickIdx + 1; i < len(history); i++ {
				h := history[i]
				if h.Action == "fill" && h.Selector == sel && (val == "" || h.Value == val) {
					return true
				}
			}
			return false
		}

		// For click, check if we already clicked this selector after the last fill in history
		if act == "click" {
			lastFillIdx := -1
			for i := len(history) - 1; i >= 0; i-- {
				if history[i].Action == "fill" {
					lastFillIdx = i
					break
				}
			}
			for i := lastFillIdx + 1; i < len(history); i++ {
				h := history[i]
				if h.Action == "click" && h.Selector == sel {
					return true
				}
			}
			return false
		}

		// Fallback to checking success status of previous attempts
		for _, h := range history {
			if h.Action == act && h.Selector == sel && (val == "" || h.Value == val) {
				if h.Success {
					return true
				}
			}
		}
		return false
	}

	// 1. Check for external domain / OAuth redirect
	targetParsed, errT := url.Parse(targetURL)
	currentParsed, errC := url.Parse(currentURLStr)
	if errT == nil && errC == nil {
		if currentParsed.Host != targetParsed.Host && currentParsed.Host != "" {
			// External domain or OAuth redirect
			reason = fmt.Sprintf("Redirected to external domain / OAuth provider: %s", currentParsed.Host)
			needsReview = true
			return "", "", "", reason, true, true
		}
	}

	// Define list of credential pairs to try:
	credentials := []struct {
		user string
		pass string
	}{
		{"admin", "admin"},
	}

	// Determine how many credential attempts we have made by counting previous successful clicks/submits
	submitAttempts := 0
	for _, h := range history {
		reasoning := strings.ToLower(h.Reasoning)
		if h.Action == "click" && (reasoning == "clicking submit button" || reasoning == "clicking login button") {
			submitAttempts++
		}
	}

	// 1b. Check if we have exhausted all credentials, or if we have no login form
	if submitAttempts >= len(credentials) {
		reason = "All authentication credential pairs failed. Aborting auth discovery."
		return "finish", "", "", reason, true, false
	}

	defaultUser := credentials[submitAttempts].user
	defaultPass := credentials[submitAttempts].pass

	var loginFormFound bool
	var usernameSel, passwordSel, submitSel string

	// Scan forms for login fields
	for _, f := range actionRes.Forms {
		var uInput, pInput, sInput browser.BrowserElement
		var hasUser, hasPass bool
		for _, in := range f.Inputs {
			tLower := strings.ToLower(in.Type)
			nLower := strings.ToLower(in.Name)
			idLower := strings.ToLower(in.ID)

			if tLower == "password" || strings.Contains(nLower, "pass") || strings.Contains(idLower, "pass") || strings.Contains(nLower, "pwd") {
				pInput = in
				hasPass = true
			}
			if tLower == "email" || tLower == "text" ||
				strings.Contains(nLower, "user") || strings.Contains(idLower, "user") ||
				strings.Contains(nLower, "email") || strings.Contains(idLower, "email") ||
				strings.Contains(nLower, "login") || strings.Contains(idLower, "login") ||
				strings.Contains(nLower, "uname") ||
				strings.Contains(nLower, "uid") || strings.Contains(idLower, "uid") ||
				strings.Contains(nLower, "userid") || strings.Contains(idLower, "userid") ||
				strings.Contains(nLower, "loginid") || strings.Contains(idLower, "loginid") ||
				strings.Contains(nLower, "customer") || strings.Contains(idLower, "customer") {
				if tLower != "password" {
					uInput = in
					hasUser = true
				}
			}
			if tLower == "submit" {
				sInput = in
			}
		}

		if hasPass {
			loginFormFound = true
			if hasUser {
				usernameSel = uInput.Selector
			}
			passwordSel = pInput.Selector
			if sInput.Selector != "" {
				submitSel = sInput.Selector
			}
			break
		}
	}

	if !loginFormFound {
		for _, f := range actionRes.Forms {
			for _, in := range f.Inputs {
				if strings.ToLower(in.Type) == "password" {
					passwordSel = in.Selector
					loginFormFound = true
					break
				}
			}
			if loginFormFound {
				break
			}
		}
	}

	if loginFormFound {
		if usernameSel != "" && !hasTried("fill", usernameSel, defaultUser) {
			return "fill", usernameSel, defaultUser, fmt.Sprintf("Filling username field with '%s'", defaultUser), false, false
		}
		if passwordSel != "" && !hasTried("fill", passwordSel, defaultPass) {
			return "fill", passwordSel, defaultPass, fmt.Sprintf("Filling password field with '%s'", defaultPass), false, false
		}
		if submitSel != "" && !hasTried("click", submitSel, "") {
			return "click", submitSel, "", "Clicking submit button", false, false
		}

		for _, b := range actionRes.Buttons {
			bText := strings.ToLower(b.Text)
			if strings.Contains(bText, "login") || strings.Contains(bText, "sign in") || strings.Contains(bText, "submit") || strings.Contains(bText, "log in") {
				if !hasTried("click", b.Selector, "") {
					return "click", b.Selector, "", "Clicking login button", false, false
				}
			}
		}
	}

	// 6. If no form is found, try navigating to a login page if a link exists
	for _, l := range actionRes.Links {
		lText := strings.ToLower(l.Text)
		lHref := strings.ToLower(l.Href)
		if strings.Contains(lText, "login") || strings.Contains(lText, "sign in") || strings.Contains(lText, "log in") ||
			strings.Contains(lHref, "login") || strings.Contains(lHref, "signin") {
			if !hasTried("click", l.Selector, "") {
				return "click", l.Selector, "", "Navigating to login page via link click", false, false
			}
		}
	}

	return "finish", "", "", "No login fields or links found. Auth discovery complete.", true, false
}

func (o *Orchestrator) getAuthCookieString(ctx context.Context, scanID string) string {
	cookiesJSON, err := o.db.GetAuthCookies(ctx, scanID)
	if err != nil || cookiesJSON == "" {
		return ""
	}

	var cookies []browser.Cookie
	if err := json.Unmarshal([]byte(cookiesJSON), &cookies); err != nil {
		return ""
	}

	var cookiePairs []string
	for _, c := range cookies {
		cookiePairs = append(cookiePairs, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}
	return strings.Join(cookiePairs, "; ")
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
		// Deterministic tech stack detection — no AI involved.
		fingerprint := scanner.DetectTechStack(reconData.Headers, reconData.Cookies)
		detectedTechs := strings.Join(fingerprint.Technologies, ", ")
		authModel := fingerprint.AuthModel
		_, err = o.db.ExecContext(ctx,
			"UPDATE scans SET detected_technologies = ?, auth_model = ? WHERE id = ?",
			detectedTechs, authModel, scanID,
		)
		if err != nil {
			log.Printf("[Orchestrator] [WARNING] Failed to save tech stack for scan %s: %v", scanID, err)
		}
		log.Printf("[Orchestrator] [Recon] Detected: %s | Auth: %s", detectedTechs, authModel)
		return nil

	case ModuleCrawlStatic:
		cookieStr := o.getAuthCookieString(ctx, scanID)
		cm := crawler.NewCrawlManager(scanID, o.proxyPort)
		return cm.Crawl(ctx, scanID, targetURL, cookieStr, func(msg string) {
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
		}, func(form browser.DiscoveredForm) {
			_, err := o.db.SaveForm(ctx, storage.FormInput{
				ScanID:   scanID,
				URL:      form.URL,
				Action:   form.Action,
				Method:   form.Method,
				Selector: form.Selector,
				Inputs:   form.Inputs,
			})
			if err != nil {
				log.Printf("[Orchestrator] [ERROR] Failed to save form %s: %v", form.Action, err)
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
		return o.runAgentXss(ctx, scanID, targetURL, onLog)

	case ModuleSqliBasic:
		return o.runAgentSqli(ctx, scanID, targetURL, onLog)

	case ModuleSqliAgent:
		return o.runAgentSqliAgent(ctx, scanID, targetURL, onLog)

	case ModuleCsrfBasic:
		return o.runAgentCsrf(ctx, scanID, targetURL)

	case ModulePathTraversal:
		return o.runAgentPathTraversal(ctx, scanID, targetURL)

	case ModuleNuclei:
		return o.runNucleiScan(ctx, scanID, targetURL, onLog)



	case ModuleAuthDiscovery:
		onLog("[AGENT] Starting autonomous authentication discovery...")
		browserClient := o.browserClient

		type SavedAction struct {
			Action   string `json:"action"`
			Selector string `json:"selector"`
			Value    string `json:"value"`
		}

		authCtx, authCancel := context.WithTimeout(ctx, 300*time.Second)
		defer authCancel()

		u, parseErr := url.Parse(targetURL)
		if parseErr != nil {
			onLog("[AGENT] [ERROR] Invalid target URL for host extraction")
			return parseErr
		}
		host := u.Host

		// Try to fetch memory flow
		memoryJSON, err := o.db.GetWorkflowMemory(authCtx, host, "login")
		if err == nil && memoryJSON != "" {
			onLog(fmt.Sprintf("[AGENT] [MEMORY] Discovered saved login sequence for host: %s. Replaying...", host))
			var savedActions []SavedAction
			if err := json.Unmarshal([]byte(memoryJSON), &savedActions); err == nil && len(savedActions) > 0 {
				replaySuccess := true
				for idx, step := range savedActions {
					onLog(fmt.Sprintf("[AGENT] [MEMORY-REPLAY] Step %d: %s on %s (val: %s)", idx+1, step.Action, step.Selector, step.Value))
					actionReq := browser.ActionRequest{
						ScanID:    scanID,
						WorkerID:  "auth",
						Action:    step.Action,
						Selector:  step.Selector,
						Value:     step.Value,
						ProxyPort: o.proxyPort,
					}
					if idx == 0 {
						actionReq.URL = targetURL
						actionReq.Action = "navigate"
					}

					execRes, err := browserClient.ExecuteAction(authCtx, actionReq)
					if err == nil && execRes != nil && execRes.ScreenshotBase64 != "" {
						o.publishBrowserScreenshot(scanID, execRes.ScreenshotBase64)
					}
					if err != nil || (execRes != nil && !execRes.Success) {
						replaySuccess = false
						onLog(fmt.Sprintf("[AGENT] [MEMORY-FAIL] Action failed: %s", step.Selector))
						break
					}

					if idx == 0 && step.Action != "navigate" {
						actionReq.URL = ""
						actionReq.Action = step.Action
						execRes2, err2 := browserClient.ExecuteAction(authCtx, actionReq)
						if err2 == nil && execRes2 != nil && execRes2.ScreenshotBase64 != "" {
							o.publishBrowserScreenshot(scanID, execRes2.ScreenshotBase64)
						}
						if err2 != nil || (execRes2 != nil && !execRes2.Success) {
							replaySuccess = false
							onLog(fmt.Sprintf("[AGENT] [MEMORY-FAIL] Input step failed: %s", step.Selector))
							break
						}
					}
					time.Sleep(500 * time.Millisecond)
				}

				if replaySuccess {
					finalCheckRes, err := browserClient.ExecuteAction(authCtx, browser.ActionRequest{
						ScanID:    scanID,
						WorkerID:  "auth",
						Action:    "wait",
						ProxyPort: o.proxyPort,
					})
					if err == nil && finalCheckRes != nil {
						_, _, _, _, finish, _ := o.decideDeterministicAuthAction(authCtx, scanID, finalCheckRes, targetURL, nil)
						if finish {
							onLog("[AGENT] [MEMORY-SUCCESS] Replay completed successfully! Authentication bypass state confirmed.")
							if len(finalCheckRes.Cookies) > 0 {
								cookiesJSON, _ := json.Marshal(finalCheckRes.Cookies)
								_ = o.db.SaveAuthCookies(authCtx, scanID, string(cookiesJSON))
							}
							return nil
						}
					}
				}
				onLog("[AGENT] [HEAL] Cached login flow was unsuccessful. Initiating AI ReAct healing process...")
			}
		}

		maxSteps := 10
		consecutiveFailures := 0
		currentStep, _ := o.db.GetLastJournalStep(authCtx, scanID)

		localAI, isLocal := o.aiClient.(*ai.LocalServiceClient)

		for step := currentStep + 1; step <= currentStep+maxSteps; step++ {
			select {
			case <-authCtx.Done():
				onLog("[AGENT] Auth discovery budget timeout reached. Halting module.")
				return nil
			default:
			}

			if consecutiveFailures >= 3 {
				onLog("[AGENT] [CIRCUIT BREAKER] 3 consecutive action failures detected. Aborting auth discovery.")
				break
			}

			onLog(fmt.Sprintf("[AGENT] Step %d: Fetching current state...", step))

			actionReq := browser.ActionRequest{
				ScanID:    scanID,
				WorkerID:  "auth",
				URL:       targetURL,
				Action:    "navigate",
				ProxyPort: o.proxyPort,
			}
			if step > 1 {
				actionReq.URL = ""
				actionReq.Action = "wait"
			}

			actionRes, err := browserClient.ExecuteAction(authCtx, actionReq)
			if err == nil && actionRes != nil && actionRes.ScreenshotBase64 != "" {
				o.publishBrowserScreenshot(scanID, actionRes.ScreenshotBase64)
			}
			if err != nil {
				onLog(fmt.Sprintf("[AGENT] [ERROR] Browser state fetch failed: %v", err))
				consecutiveFailures++
				continue
			}

			// Check if already authenticated
			_, _, _, _, finish, _ := o.decideDeterministicAuthAction(authCtx, scanID, actionRes, targetURL, nil)
			if finish {
				onLog("[AGENT] Authentication successful! Preserving sequence to workflow memory.")
				history, _ := o.db.ListJournalEntries(authCtx, scanID)
				var successfulSteps []SavedAction
				for _, h := range history {
					if h.Success && h.Action != "wait" && h.Action != "navigate" {
						successfulSteps = append(successfulSteps, SavedAction{
							Action:   h.Action,
							Selector: h.Selector,
							Value:    h.Value,
						})
					}
				}
				if len(successfulSteps) > 0 {
					stepsJSON, _ := json.Marshal(successfulSteps)
					_ = o.db.SaveWorkflowMemory(authCtx, host, "login", string(stepsJSON))
				}
				if len(actionRes.Cookies) > 0 {
					cookiesJSON, _ := json.Marshal(actionRes.Cookies)
					_ = o.db.SaveAuthCookies(authCtx, scanID, string(cookiesJSON))
					onLog(fmt.Sprintf("[AGENT] Persisted %d session cookies.", len(actionRes.Cookies)))
				}
				break
			}

			// ReAct Planning with AXTree
			history, _ := o.db.ListJournalEntries(authCtx, scanID)
			historyJSON, _ := json.Marshal(history)
			linksJSON, _ := json.Marshal(actionRes.Links)
			buttonsJSON, _ := json.Marshal(actionRes.Buttons)
			formsJSON, _ := json.Marshal(actionRes.Forms)

			prompt := fmt.Sprintf(`
You are LastResort, an autonomous browser pentesting agent.
Your current goal is to find a way to authenticate (log in) to the target application.
Current Page URL: %s
Page Title: %s
Accessibility Tree (AXTree):
%s

Interactive Elements Available:
Links: %s
Buttons: %s
Forms: %s

History of previous actions in this scan:
%s

Decide on the next single best action to take to advance toward authentication.
Your response MUST be in JSON format matching this schema:
{
  "thought": "Your reasoning here",
  "action": "click" | "fill",
  "selector": "CSS selector to interact with",
  "value": "Value to type (if action is fill)",
  "finish": true/false
}
`, actionRes.CurrentURL, actionRes.PageTitle, actionRes.AXTree, string(linksJSON), string(buttonsJSON), string(formsJSON), string(historyJSON))

			var resStr string
			if isLocal {
				resStr, err = localAI.CallLLM(authCtx, prompt, true)
			} else {
				err = fmt.Errorf("local AI service client is unavailable")
			}

			if err != nil {
				onLog(fmt.Sprintf("[AGENT] [ERROR] AI planning call failed: %v", err))
				consecutiveFailures++
				continue
			}

			var decision struct {
				Thought  string `json:"thought"`
				Action   string `json:"action"`
				Selector string `json:"selector"`
				Value    string `json:"value"`
				Finish   bool   `json:"finish"`
			}
			if err := json.Unmarshal([]byte(resStr), &decision); err != nil {
				onLog(fmt.Sprintf("[AGENT] [ERROR] Failed to parse AI decision JSON: %v", err))
				consecutiveFailures++
				continue
			}

			onLog(fmt.Sprintf("[AGENT] Thought: %s", decision.Thought))
			onLog(fmt.Sprintf("[AGENT] Decision: %s on %s (val: %s)", decision.Action, decision.Selector, decision.Value))

			if decision.Finish {
				onLog("[AGENT] AI signaled completion of authentication flow.")
				break
			}

			// Execute chosen action
			execReq := browser.ActionRequest{
				ScanID:    scanID,
				WorkerID:  "auth",
				Action:    decision.Action,
				Selector:  decision.Selector,
				Value:     decision.Value,
				ProxyPort: o.proxyPort,
			}

			execRes, err := browserClient.ExecuteAction(authCtx, execReq)
			if err == nil && execRes != nil && execRes.ScreenshotBase64 != "" {
				o.publishBrowserScreenshot(scanID, execRes.ScreenshotBase64)
			}

			success := (err == nil && execRes != nil && execRes.Success)
			var failureReason string
			if err != nil {
				failureReason = err.Error()
			} else if execRes != nil {
				failureReason = execRes.FailureReason
			}

			if !success {
				consecutiveFailures++
				onLog(fmt.Sprintf("[AGENT] [ERROR] Action execution failed: %s", failureReason))
			} else {
				consecutiveFailures = 0
			}

			// Record in journal
			_ = o.db.SaveJournalEntry(authCtx, &storage.JournalEntry{
				ScanID:    scanID,
				Step:      step,
				Action:    decision.Action,
				Selector:  decision.Selector,
				Value:     decision.Value,
				Success:   success,
				Error:     failureReason,
				Reasoning: decision.Thought,
				Result:    execRes,
			})

			time.Sleep(500 * time.Millisecond)
		}
		return nil

	case ModuleVisualExploit:
		onLog("[AGENT] Starting visual exploitation phase...")
		rows, err := o.db.QueryContext(ctx, "SELECT id, vulnerability_type, endpoint, payload FROM findings WHERE scan_id = ? AND is_false_positive = 0 AND payload != '' AND category = ? LIMIT 10", scanID, storage.StateVerifiedFinding)
		if err != nil {
			return nil
		}
		defer rows.Close()

		for rows.Next() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			var fID int64
			var vulnType, endpoint, payload string
			if err := rows.Scan(&fID, &vulnType, &endpoint, &payload); err != nil {
				continue
			}
			onLog(fmt.Sprintf("[AGENT] Visually demonstrating %s at %s", vulnType, endpoint))
			
			var execErr error
			if vulnType == "XSS" || vulnType == "SQL Injection" {
				_, execErr = o.browserClient.ExecuteAction(ctx, browser.ActionRequest{
					ScanID:    scanID,
					WorkerID:  "visual_exploit",
					URL:       endpoint,
					Action:    "navigate",
					ProxyPort: o.proxyPort,
				})
			}
			if execErr == nil {
				time.Sleep(2 * time.Second)
				actionRes, _ := o.browserClient.ExecuteAction(ctx, browser.ActionRequest{
					ScanID:    scanID,
					WorkerID:  "visual_exploit",
					URL:       "",
					Action:    "wait",
					ProxyPort: o.proxyPort,
				})
				if actionRes != nil && actionRes.ScreenshotBase64 != "" {
					o.publishBrowserScreenshot(scanID, actionRes.ScreenshotBase64)
				}
			}
		}
		return nil

	case ModuleReport:
		gen := report.NewGenerator(o.db, o.aiClient)
		_, htmlPath, err := gen.GenerateScanReport(ctx, scanID)
		if err != nil {
			return err
		}
		// Trim "data/" prefix so frontend can use it with the static route /reports/
		webPath := strings.TrimPrefix(htmlPath, "data/")
		GlobalBroker.Publish(Event{
			ScanID:    scanID,
			Type:      "report.generated",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"path": webPath,
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
	case ModuleHeaders, ModuleCors, ModuleXssReflected, ModuleSqliBasic, ModuleRateLimitBasic, ModuleNuclei:
		return true
	}
	return false
}

// emitNewFindings queries findings added since we started tracking and publishes finding.new events.
// We use a simple approach: query the most recent findings for this scan and emit them.
func (o *Orchestrator) emitNewFindings(ctx context.Context, scanID string) {
	// Apply strict filtration: Only emit HIGH/CRITICAL severity or specific actionable exploit types.
	// This prevents the UI from being flooded with hundreds of low-level misconfigurations.
	rows, err := o.db.QueryContext(ctx,
		`SELECT id, title, severity, vulnerability_type, endpoint, confidence, category
		 FROM findings 
		 WHERE scan_id = ? 
		   AND is_false_positive = 0 
		   AND (severity IN ('HIGH', 'CRITICAL') OR vulnerability_type IN ('SQL Injection', 'XSS', 'CSRF', 'Path Traversal'))
		 ORDER BY created_at DESC LIMIT 10`, scanID)
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

func (o *Orchestrator) runNucleiScan(ctx context.Context, scanID, targetURL string, onLog func(string)) error {
	if !attack.ToolAvailable("nuclei") {
		o.publishAgentLog(scanID, "[Orchestrator] [WARNING] Nuclei is missing. Downgrading gracefully to internal Header/CORS/Misconfiguration checks.")
		return nil
	}

	log.Printf("[Orchestrator] [Nuclei] Shelling out to Nuclei on %s", targetURL)
	cookieStr := o.getAuthCookieString(ctx, scanID)
	nucleiFindings, err := attack.RunNucleiScan(ctx, targetURL, o.proxyPort, cookieStr, onLog)
	if err != nil {
		log.Printf("[Orchestrator] [WARNING] Nuclei scan failed: %v", err)
		return nil
	}

	for _, f := range nucleiFindings {
		_ = o.db.IncrementAttackExecuted(ctx, scanID)
		_ = o.db.IncrementAttackVerified(ctx, scanID)
		findingID, err := o.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            scanID,
			Title:             f.Title,
			Description:       fmt.Sprintf("%s\n\nVerification: Verified by Nuclei safe template rules.", f.Evidence),
			Severity:          f.Severity,
			VulnerabilityType: f.VulnerabilityType,
			Endpoint:          f.Endpoint,
			Payload:           f.Payload,
			ResponseStatus:    200,
			Confidence:        0.90,
			Category:          storage.StatePotentialFinding,
		}, storage.EvidenceInput{
			FlowID:          0,
			EvidenceType:    storage.EvidenceDOM,
			RequestExcerpt:  fmt.Sprintf("Nuclei vulnerability scan: %s", f.Endpoint),
			ResponseExcerpt: f.Evidence,
		})
		if err == nil {
			vr := &storage.VerificationResult{
				EndpointURL:     f.Endpoint,
				Payload:         f.Payload,
				VerifiedAt:      time.Now(),
				Verified:        true,
				Confidence:      0.90,
				Method:          storage.VerificationDOMMarker,
				EvidenceSummary: fmt.Sprintf("Nuclei verified vulnerability details: %s", f.Evidence),
			}
			verifID, verifErr := o.db.SaveVerification(ctx, findingID, scanID, vr)
			if verifErr == nil {
				if _, updateErr := o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID); updateErr != nil {
					o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to update finding category: %v", updateErr))
				}
			} else {
				o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save verification: %v", verifErr))
			}
		} else {
			o.publishAgentLog(scanID, fmt.Sprintf("[ERROR] Failed to save finding: %v", err))
		}
	}

	return nil
}



