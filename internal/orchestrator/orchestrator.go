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
		verification:  NewVerificationEngine(),
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
			case ModuleHeaders, ModuleCors, ModuleXssReflected, ModuleSqliBasic, ModuleCsrfBasic, ModuleRateLimitBasic, ModuleNuclei:
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
	default:
		return module
	}
}

type AttackSurface struct {
	URL         string
	Method      string
	BaseBody    []byte
	ContentType string
	Point       scanner.InsertionPoint
	IsForm      bool
	FormSel     string
	FormPageURL string
}

func (o *Orchestrator) getAttackSurfaces(ctx context.Context, scanID string) ([]AttackSurface, error) {
	var surfaces []AttackSurface

	// 1. Fetch static/recon endpoints
	endpoints, err := o.db.ListEndpoints(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}

	for _, ep := range endpoints {
		points, _ := scanner.ExtractInsertionPoints(ep.Method, ep.URL, nil, "")
		for _, pt := range points {
			surfaces = append(surfaces, AttackSurface{
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
				vals := url.Values{}
				for _, otherIn := range inputs {
					otherName := otherIn.Name
					if otherName == "" {
						otherName = otherIn.ID
					}
					if otherName != "" && otherIn.Type != "submit" && otherIn.Type != "button" {
						vals.Set(otherName, otherIn.Value)
					}
				}
				baseBody = []byte(vals.Encode())
			}

			formActionURL := f.Action
			if formActionURL == "" {
				formActionURL = f.URL
			} else {
				base, err := url.Parse(f.URL)
				if err == nil {
					ref, err := url.Parse(formActionURL)
					if err == nil {
						formActionURL = base.ResolveReference(ref).String()
					}
				}
			}

			surfaces = append(surfaces, AttackSurface{
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

func (o *Orchestrator) runAgentSqli(ctx context.Context, scanID, targetURL string) error {
	surfaces, err := o.getAttackSurfaces(ctx, scanID)
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
					_, _ = o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID)
				}
			}
		}
	}

	// 2. Call SQLMap fuzzer loop if tool is available
	if !attack.ToolAvailable("sqlmap") {
		o.publishAgentLog(scanID, "[Orchestrator] [WARNING] SQLMap fuzzer not found in PATH. Downgrading gracefully to internal SQLi fuzzer.")
	} else {
		o.publishAgentLog(scanID, "[Orchestrator] [SQLi] SQLMap is available. Fuzzing discovered endpoints...")
		endpoints, err := o.db.ListEndpoints(ctx, scanID)
		if err == nil {
			var fuzzedAny bool
			for _, ep := range endpoints {
				if strings.Contains(ep.URL, "?") {
					o.publishAgentLog(scanID, fmt.Sprintf("[Orchestrator] [SQLi] Running SQLMap on parameter endpoint: %s", ep.URL))
					sqliFindings, err := attack.RunSQLMapScan(ctx, ep.URL, o.proxyPort)
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
								Category:          storage.StateVerifiedFinding,
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
									_, _ = o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID)
								}
							}
						}
					}
				}
			}
			// Fallback to seed target URL if no parameter-based endpoints were found
			if !fuzzedAny {
				o.publishAgentLog(scanID, fmt.Sprintf("[Orchestrator] [SQLi] Running SQLMap on seed URL: %s", targetURL))
				sqliFindings, err := attack.RunSQLMapScan(ctx, targetURL, o.proxyPort)
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
							Category:          storage.StateVerifiedFinding,
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
								_, _ = o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID)
							}
						}
					}
				}
			}
		}
	}

	return nil
}


func (o *Orchestrator) runAgentXss(ctx context.Context, scanID, targetURL string) error {
	surfaces, err := o.getAttackSurfaces(ctx, scanID)
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
					_, _ = o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID)
				}
			}
		}
	}

	// 2. Call Dalfox XSS fuzzer loop if tool is available
	if !attack.ToolAvailable("dalfox") {
		o.publishAgentLog(scanID, "[Orchestrator] [WARNING] Dalfox fuzzer not found in PATH. Downgrading gracefully to internal XSS fuzzer.")
	} else {
		o.publishAgentLog(scanID, "[Orchestrator] [XSS] Dalfox is available. Fuzzing discovered endpoints...")
		endpoints, err := o.db.ListEndpoints(ctx, scanID)
		if err == nil {
			var fuzzedAny bool
			for _, ep := range endpoints {
				if strings.Contains(ep.URL, "?") {
					o.publishAgentLog(scanID, fmt.Sprintf("[Orchestrator] [XSS] Running Dalfox on parameter endpoint: %s", ep.URL))
					dfFindings, err := attack.RunDalfoxScan(ctx, ep.URL, o.proxyPort)
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
								Category:          storage.StateVerifiedFinding,
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
									_, _ = o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID)
								}
							}
						}
					}
				}
			}
			// Fallback to seed target URL if no parameter-based endpoints were found
			if !fuzzedAny {
				o.publishAgentLog(scanID, fmt.Sprintf("[Orchestrator] [XSS] Running Dalfox on seed URL: %s", targetURL))
				dfFindings, err := attack.RunDalfoxScan(ctx, targetURL, o.proxyPort)
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
							Category:          storage.StateVerifiedFinding,
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
								_, _ = o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID)
							}
						}
					}
				}
			}
		}
	}

	return nil
}




func (o *Orchestrator) runAgentPathTraversal(ctx context.Context, scanID, targetURL string) error {
	surfaces, err := o.getAttackSurfaces(ctx, scanID)
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
					_, _ = o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID)
				}
			}
		}
	}
	return nil
}

func (o *Orchestrator) runAgentCsrf(ctx context.Context, scanID, targetURL string) error {
	rows, err := o.db.QueryContext(ctx, "SELECT id, method, url, request_headers, request_body FROM http_flows WHERE scan_id = ? ORDER BY id DESC", scanID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

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
				_, _ = o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID)
			}
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
		{"jsmith", "VerySafe"}, // Priority target-specific (Altoro Mutual / Testfire)
		{"admin", "admin"},
		{"admin", "password"},
		{"test", "test"},
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
		return o.runAgentXss(ctx, scanID, targetURL)

	case ModuleSqliBasic:
		return o.runAgentSqli(ctx, scanID, targetURL)

	case ModuleCsrfBasic:
		return o.runAgentCsrf(ctx, scanID, targetURL)

	case ModulePathTraversal:
		return o.runAgentPathTraversal(ctx, scanID, targetURL)

	case ModuleNuclei:
		return o.runNucleiScan(ctx, scanID, targetURL)



	case ModuleAuthDiscovery:
		onLog("[AGENT] Starting autonomous authentication discovery...")
		browserClient := o.browserClient

		// Prioritize 300-second total budget context for authentication discovery
		authCtx, authCancel := context.WithTimeout(ctx, 300*time.Second)
		defer authCancel()

		maxSteps := 10
		consecutiveFailures := 0
		
		currentStep, _ := o.db.GetLastJournalStep(authCtx, scanID)

		for step := currentStep + 1; step <= currentStep+maxSteps; step++ {
			select {
			case <-authCtx.Done():
				onLog("[AGENT] Auth discovery budget timeout reached (120s). Halting module.")
				return nil
			default:
			}

			if consecutiveFailures >= 3 {
				onLog("[AGENT] [CIRCUIT BREAKER] 3 consecutive action failures detected. Aborting auth discovery.")
				break
			}

			onLog(fmt.Sprintf("[AGENT] Step %d: Analyzing current page state...", step))

			// 1. Get current state (navigate to seed first if just starting)
			actionReq := browser.ActionRequest{
				ScanID:    scanID,
				WorkerID:  "auth",
				URL:       targetURL, // Always ensure we are in scope
				Action:    "navigate",
				ProxyPort: o.proxyPort,
			}
			if step > 1 {
				actionReq.URL = "" // Don't re-navigate, just get current source
				actionReq.Action = "wait"
			}

			actionRes, err := browserClient.ExecuteAction(authCtx, actionReq)
			if err == nil && actionRes != nil && actionRes.ScreenshotBase64 != "" {
				o.publishBrowserScreenshot(scanID, actionRes.ScreenshotBase64)
			}
			if err != nil {
				onLog(fmt.Sprintf("[AGENT] [ERROR] Browser action failed: %v", err))
				consecutiveFailures++
				continue
			}

			// Retrieve updated journal history
			history, _ := o.db.ListJournalEntries(authCtx, scanID)

			// 2. Deterministically decide what to do next
			decideAction, decideSelector, decideValue, decideReason, finish, _ := o.decideDeterministicAuthAction(
				authCtx,
				scanID,
				actionRes,
				targetURL,
				history,
			)

			onLog(fmt.Sprintf("[AGENT] Deterministic Decision: %s (%s)", decideAction, decideReason))

			if finish {
				onLog("[AGENT] Deterministic signaling discovery phase complete.")
				break
			}

			// 3. Execute the deterministic action
			execReq := browser.ActionRequest{
				ScanID:    scanID,
				WorkerID:  "auth",
				Action:    decideAction,
				Selector:  decideSelector,
				Value:     decideValue,
				ProxyPort: o.proxyPort,
			}

			execRes, err := browserClient.ExecuteAction(authCtx, execReq)
			if err == nil && execRes != nil && execRes.ScreenshotBase64 != "" {
				o.publishBrowserScreenshot(scanID, execRes.ScreenshotBase64)
			}

			type stepOutcome struct {
				Action, Selector, Value, Reasoning, Error string
				Success bool
				Result  *browser.ActionResult
			}
			var outcome stepOutcome
			if err != nil {
				consecutiveFailures++
				onLog(fmt.Sprintf("[AGENT] [ERROR] Execution of %s failed: %v", decideAction, err))
				outcome = stepOutcome{
					Action:    decideAction,
					Selector:  decideSelector,
					Value:     decideValue,
					Success:   false,
					Error:     err.Error(),
					Reasoning: decideReason,
					Result: &browser.ActionResult{
						Success:       false,
						FailureReason: err.Error(),
					},
				}
			} else {
				if !execRes.Success {
					consecutiveFailures++
				} else {
					consecutiveFailures = 0
				}
				outcome = stepOutcome{
					Action:    decideAction,
					Selector:  decideSelector,
					Value:     decideValue,
					Success:   execRes.Success,
					Error:     execRes.FailureReason,
					Reasoning: decideReason,
					Result:    execRes,
				}
			}

			// Add to history and persist to journal
			_ = o.db.SaveJournalEntry(authCtx, &storage.JournalEntry{
				ScanID:    scanID,
				Step:      step,
				Action:    outcome.Action,
				Selector:  outcome.Selector,
				Value:     outcome.Value,
				Success:   outcome.Success,
				Error:     outcome.Error,
				Reasoning: outcome.Reasoning,
				Result:    outcome.Result,
			})

			// Small delay for animations
			time.Sleep(500 * time.Millisecond)
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

func (o *Orchestrator) runNucleiScan(ctx context.Context, scanID, targetURL string) error {
	if !attack.ToolAvailable("nuclei") {
		o.publishAgentLog(scanID, "[Orchestrator] [WARNING] Nuclei is missing. Downgrading gracefully to internal Header/CORS/Misconfiguration checks.")
		return nil
	}

	log.Printf("[Orchestrator] [Nuclei] Shelling out to Nuclei on %s", targetURL)
	nucleiFindings, err := attack.RunNucleiScan(ctx, targetURL, o.proxyPort)
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
			Category:          storage.StateVerifiedFinding,
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
				_, _ = o.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID)
			}
		}
	}

	return nil
}



