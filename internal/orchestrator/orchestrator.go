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
	db            *storage.DB
	aiClient      aiv1connect.AiServiceClient
	browserClient *browser.Client
	proxyPort     int
	verification  *VerificationEngine
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

type AttackSurface struct {
	URL         string
	Method      string
	BaseBody    []byte
	ContentType string
	Point       scanner.InsertionPoint
	IsForm      bool
	FormSel     string
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

			surfaces = append(surfaces, AttackSurface{
				URL:         f.URL,
				Method:      f.Method,
				BaseBody:    baseBody,
				ContentType: "application/x-www-form-urlencoded",
				Point:       pt,
				IsForm:      true,
				FormSel:     f.Selector,
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
	method string,
	urlStr string,
	body []byte,
) (*browser.ActionResult, error) {
	methodUpper := strings.ToUpper(method)
	if methodUpper == "GET" || len(body) == 0 {
		actionReq := browser.ActionRequest{
			ScanID:    scanID,
			URL:       urlStr,
			Action:    "navigate",
			ProxyPort: o.proxyPort,
		}
		return o.browserClient.ExecuteAction(ctx, actionReq)
	}

	_, _ = o.browserClient.ExecuteAction(ctx, browser.ActionRequest{
		ScanID:    scanID,
		URL:       urlStr,
		Action:    "navigate",
		ProxyPort: o.proxyPort,
	})

	script := makeFormSubmitScript(urlStr, methodUpper, body)

	actionReq := browser.ActionRequest{
		ScanID:    scanID,
		Action:    "evaluate",
		Value:     script,
		ProxyPort: o.proxyPort,
	}
	return o.browserClient.ExecuteAction(ctx, actionReq)
}

func (o *Orchestrator) runAgentSqli(ctx context.Context, scanID, targetURL string) error {
	surfaces, err := o.getAttackSurfaces(ctx, scanID)
	if err != nil {
		return err
	}

	for _, surf := range surfaces {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		payloadReq := connect.NewRequest(&aiv1.GenerateAttackPayloadRequest{
			HypothesisTitle:       fmt.Sprintf("SQL Injection in %s", surf.Point.Name),
			HypothesisDescription: fmt.Sprintf("Potential SQL injection vulnerability detected in parameter %s at %s.", surf.Point.Name, surf.URL),
			Endpoint:              surf.URL,
			Method:                surf.Method,
		})

		start := time.Now()
		payloadRes, err := o.aiClient.GenerateAttackPayload(ctx, payloadReq)
		o.trackGeminiCall(ctx, scanID, time.Since(start))
		if err != nil {
			continue
		}

		_ = o.db.IncrementAttackExecuted(ctx, scanID)

		injectedURL, injectedBody := scanner.BuildInjectedRequest(surf.Method, surf.URL, surf.BaseBody, surf.ContentType, surf.Point, payloadRes.Msg.Body)

		attemptID, _ := o.db.SaveAttackAttempt(ctx, storage.AttackAttemptInput{
			ScanID:           scanID,
			AttackType:       "SQL Injection",
			Endpoint:         injectedURL,
			Payload:          payloadRes.Msg.Body,
			RequestCaptured:  fmt.Sprintf("%s %s\nContent-Type: %s\n\n%s", surf.Method, injectedURL, surf.ContentType, string(injectedBody)),
			ResponseCaptured: "",
			EvidenceFound:    "",
			Result:           "failed",
		})

		actionRes, err := o.executeDeterministicAttack(ctx, scanID, surf.Method, injectedURL, injectedBody)
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

		vr := o.verification.VerifySQLi(ctx, injectedURL, payloadRes.Msg.Body, actionRes.PageSource, actionRes.ScreenshotBase64)

		if !vr.Verified {
			_ = o.db.IncrementAttackFailed(ctx, scanID)
			continue
		}

		_ = o.db.IncrementAttackVerified(ctx, scanID)
		_, _ = o.db.ExecContext(ctx, "UPDATE attack_attempts SET result = ?, evidence_found = ? WHERE id = ?", "verified", vr.EvidenceSummary, attemptID)

		findingID, err := o.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            scanID,
			Title:             "[AI-VERIFIED] SQL Injection in Parameter: " + surf.Point.Name,
			Description:       payloadRes.Msg.Explanation + "\n\nVerification: " + vr.EvidenceSummary,
			Severity:          "HIGH",
			VulnerabilityType: "SQL Injection",
			Endpoint:          injectedURL,
			Payload:           payloadRes.Msg.Body,
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
	return nil
}

func (o *Orchestrator) runAgentXss(ctx context.Context, scanID, targetURL string) error {
	surfaces, err := o.getAttackSurfaces(ctx, scanID)
	if err != nil {
		return err
	}

	for _, surf := range surfaces {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		payloadReq := connect.NewRequest(&aiv1.GenerateAttackPayloadRequest{
			HypothesisTitle:       fmt.Sprintf("Cross-Site Scripting in %s", surf.Point.Name),
			HypothesisDescription: fmt.Sprintf("Potential XSS vulnerability detected in parameter %s at %s.", surf.Point.Name, surf.URL),
			Endpoint:              surf.URL,
			Method:                surf.Method,
		})

		start := time.Now()
		payloadRes, err := o.aiClient.GenerateAttackPayload(ctx, payloadReq)
		o.trackGeminiCall(ctx, scanID, time.Since(start))
		if err != nil {
			continue
		}

		_ = o.db.IncrementAttackExecuted(ctx, scanID)

		injectedURL, injectedBody := scanner.BuildInjectedRequest(surf.Method, surf.URL, surf.BaseBody, surf.ContentType, surf.Point, payloadRes.Msg.Body)

		attemptID, _ := o.db.SaveAttackAttempt(ctx, storage.AttackAttemptInput{
			ScanID:           scanID,
			AttackType:       "XSS",
			Endpoint:         injectedURL,
			Payload:          payloadRes.Msg.Body,
			RequestCaptured:  fmt.Sprintf("%s %s\nContent-Type: %s\n\n%s", surf.Method, injectedURL, surf.ContentType, string(injectedBody)),
			ResponseCaptured: "",
			EvidenceFound:    "",
			Result:           "failed",
		})

		actionRes, err := o.executeDeterministicAttack(ctx, scanID, surf.Method, injectedURL, injectedBody)
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

		vr := o.verification.VerifyXSS(ctx, "Reflected XSS", injectedURL, payloadRes.Msg.Body, actionRes.PageSource, actionRes.ScreenshotBase64)

		if !vr.Verified {
			_ = o.db.IncrementAttackFailed(ctx, scanID)
			continue
		}

		_ = o.db.IncrementAttackVerified(ctx, scanID)
		_, _ = o.db.ExecContext(ctx, "UPDATE attack_attempts SET result = ?, evidence_found = ? WHERE id = ?", "verified", vr.EvidenceSummary, attemptID)

		findingID, err := o.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            scanID,
			Title:             "[AI-VERIFIED] Cross-Site Scripting in Parameter: " + surf.Point.Name,
			Description:       payloadRes.Msg.Explanation + "\n\nVerification: " + vr.EvidenceSummary,
			Severity:          "HIGH",
			VulnerabilityType: "XSS",
			Endpoint:          injectedURL,
			Payload:           payloadRes.Msg.Body,
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

			actionRes, err := o.executeDeterministicAttack(ctx, scanID, surf.Method, injectedURL, injectedBody)
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
				Title:             "[AI-VERIFIED] Path Traversal in Parameter: " + surf.Point.Name,
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

		actionRes, err := o.executeDeterministicAttack(ctx, scanID, method, urlStr, body)
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
			Title:             "[AI-VERIFIED] CSRF Vulnerability on " + urlStr,
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

	var loginFormFound bool
	var usernameSel, passwordSel, submitSel string
	defaultUser, defaultPass := "admin", "admin"

	if strings.Contains(targetURL, "testfire.net") {
		defaultUser = "admin"
		defaultPass = "admin"
	}

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
			return "fill", usernameSel, defaultUser, "Filling username field", false, false
		}
		if passwordSel != "" && !hasTried("fill", passwordSel, defaultPass) {
			return "fill", passwordSel, defaultPass, "Filling password field", false, false
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
				
				// 2. Execute the AI-crafted attack (Agent-Driven)
				actionRes, err := o.executeBrowserAttack(execCtx, scanID, payloadRes.Msg)
				if err != nil {
					log.Printf("[Orchestrator] AI Attack Execution Failed for %s: %v", hyp.Title, err)
					return
				}

				// 3. Score confidence using AI verification
				scoreReq := connect.NewRequest(&aiv1.ScoreConfidenceRequest{
					VulnerabilityType: hyp.VulnerabilityType,
					Endpoint:          payloadRes.Msg.Url,
					Payload:           payloadRes.Msg.Body,
					ResponseBody:      actionRes.PageSource,
					ResponseStatus:    200, // Browser interactions don't yield raw status codes easily
				})
				scoreRes, err := o.aiClient.ScoreConfidence(execCtx, scoreReq)
				if err != nil {
					log.Printf("[Orchestrator] AI Confidence Scoring Failed for %s: %v", hyp.Title, err)
					return
				}

				// 4. Update status and save finding if verified
				isVerified := scoreRes.Msg.Confidence > 0.7 && !scoreRes.Msg.IsFalsePositive
				
				if isVerified {
					_, _ = o.db.ExecContext(execCtx, "UPDATE hypotheses SET status = ? WHERE scan_id = ? AND title = ?", "VERIFIED", scanID, hyp.Title)
					
					// Save as a Finding
					_, _ = o.db.SaveFindingWithEvidence(execCtx, storage.FindingInput{
						ScanID:            scanID,
						Title:             "[AI-VERIFIED] " + hyp.Title,
						Description:       hyp.Description + "\n\nAI Explanation: " + payloadRes.Msg.Explanation + "\n\nVerification: " + scoreRes.Msg.Explanation,
						Severity:          severityFromConfidence(float64(scoreRes.Msg.Confidence)),
						VulnerabilityType: hyp.VulnerabilityType,
						Endpoint:          payloadRes.Msg.Url,
						Payload:           payloadRes.Msg.Body,
						ResponseStatus:    200,
						Confidence:        float64(scoreRes.Msg.Confidence),
						Category:          "VERIFIED_ATTACK",
					}, storage.EvidenceInput{
						FlowID:          0, // Browser attacks don't have a single flow ID in the same way, but we should attach the screenshot
						EvidenceType:    storage.EvidenceScreenshot,
						RequestExcerpt:  fmt.Sprintf("%s %s", payloadRes.Msg.Method, payloadRes.Msg.Url),
						ResponseExcerpt: actionRes.PageSource,
					})
				} else {
					_, _ = o.db.ExecContext(execCtx, "UPDATE hypotheses SET status = ? WHERE scan_id = ? AND title = ?", "FAILED", scanID, hyp.Title)
				}

				// Record in Journal
				lastStep, _ := o.db.GetLastJournalStep(execCtx, scanID)
				_ = o.db.SaveJournalEntry(execCtx, &storage.JournalEntry{
					ScanID:    scanID,
					Step:      lastStep + 1,
					Action:    "browser_attack",
					Value:     payloadRes.Msg.Url,
					Success:   isVerified,
					Reasoning: payloadRes.Msg.Explanation,
					Result:    mapActionResult(actionRes),
				})
			}(h)
		}
		return nil

	case ModuleAuthDiscovery:
		onLog("[AGENT] Starting autonomous authentication discovery...")
		browserClient := o.browserClient

		// Prioritize 30-second total budget context for authentication discovery
		authCtx, authCancel := context.WithTimeout(ctx, 30*time.Second)
		defer authCancel()

		maxSteps := 10
		consecutiveFailures := 0
		
		currentStep, _ := o.db.GetLastJournalStep(authCtx, scanID)

		defer func() {
			// Cleanup browser session on exit
			endReq, _ := http.NewRequest("POST", "http://127.0.0.1:3010/end-session", strings.NewReader(fmt.Sprintf(`{"scanId":"%s"}`, scanID)))
			if endReq != nil {
				endReq.Header.Set("Content-Type", "application/json")
				_, _ = http.DefaultClient.Do(endReq)
			}
		}()

		for step := currentStep + 1; step <= currentStep+maxSteps; step++ {
			select {
			case <-authCtx.Done():
				onLog("[AGENT] Auth discovery budget timeout reached (30s). Halting module.")
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
				URL:       targetURL, // Always ensure we are in scope
				Action:    "navigate",
				ProxyPort: o.proxyPort,
			}
			if step > 1 {
				actionReq.URL = "" // Don't re-navigate, just get current source
				actionReq.Action = "wait"
			}

			actionRes, err := browserClient.ExecuteAction(authCtx, actionReq)
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
				Action:    decideAction,
				Selector:  decideSelector,
				Value:     decideValue,
				ProxyPort: o.proxyPort,
			}

			execRes, err := browserClient.ExecuteAction(authCtx, execReq)
			var outcome *aiv1.BrowserActionOutcome
			if err != nil {
				consecutiveFailures++
				onLog(fmt.Sprintf("[AGENT] [ERROR] Execution of %s failed: %v", decideAction, err))
				
				outcome = &aiv1.BrowserActionOutcome{
					Action:   decideAction,
					Selector: decideSelector,
					Value:    decideValue,
					Success:  false,
					Error:    err.Error(),
					Result: &aiv1.ActionResult{
						Success:       false,
						FailureReason: err.Error(),
					},
					Reasoning: decideReason,
				}
			} else {
				if !execRes.Success {
					consecutiveFailures++
				} else {
					consecutiveFailures = 0 // reset on success
				}
				
				outcome = &aiv1.BrowserActionOutcome{
					Action:    decideAction,
					Selector:  decideSelector,
					Value:     decideValue,
					Success:   execRes.Success,
					Error:     execRes.FailureReason,
					Result:    mapActionResult(execRes),
					Reasoning: decideReason,
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

func mapBrowserElements(elements []browser.BrowserElement) []*aiv1.BrowserElement {
	res := make([]*aiv1.BrowserElement, len(elements))
	for i, e := range elements {
		res[i] = &aiv1.BrowserElement{
			Text:     e.Text,
			Selector: e.Selector,
			Type:     e.Type,
			Href:     e.Href,
			Id:       e.ID,
			Name:     e.Name,
			Value:    e.Value,
		}
	}
	return res
}

func mapBrowserForms(forms []browser.BrowserForm) []*aiv1.BrowserForm {
	res := make([]*aiv1.BrowserForm, len(forms))
	for i, f := range forms {
		res[i] = &aiv1.BrowserForm{
			Selector: f.Selector,
			Action:   f.Action,
			Method:   f.Method,
			Inputs:   mapBrowserElements(f.Inputs),
		}
	}
	return res
}

func mapActionResult(res *browser.ActionResult) *aiv1.ActionResult {
	return &aiv1.ActionResult{
		Success:          res.Success,
		FailureReason:    res.FailureReason,
		CurrentUrl:       res.CurrentURL,
		PageTitle:        res.PageTitle,
		ScreenshotBase64: res.ScreenshotBase64,
		Links:            mapBrowserElements(res.Links),
		Buttons:          mapBrowserElements(res.Buttons),
		Forms:            mapBrowserForms(res.Forms),
		PageSource:       res.PageSource,
	}
}

// executeBrowserAttack performs a single AI-defined attack using the Playwright service.
func (o *Orchestrator) executeBrowserAttack(ctx context.Context, scanID string, payload *aiv1.GenerateAttackPayloadResponse) (*browser.ActionResult, error) {
	// 1. Start session/Navigate
	actionReq := browser.ActionRequest{
		ScanID:    scanID,
		URL:       payload.Url,
		Action:    "navigate",
		ProxyPort: o.proxyPort,
	}
	
	actionRes, err := o.browserClient.ExecuteAction(ctx, actionReq)
	if err != nil {
		return nil, err
	}
	
	if !actionRes.Success {
		return actionRes, nil
	}

	// 2. Perform the actual injection action
	// The AI usually provides a payload for a specific parameter.
	// For now, we attempt to find the element and fill it, or just use navigate if it's a GET param.
	// If method is GET, the payload is already in the URL from GenerateAttackPayload.
	
	if strings.ToUpper(payload.Method) == "GET" {
		return actionRes, nil
	}

	// For POST/PUT/etc, we might need to find the form and fill it.
	// This is a simplified version; a full agent would use DecideBrowserAction in a loop.
	// But for a single payload execution, we try to be smart.
	
	// If the AI didn't provide a selector, we might need to guess or ask AI.
	// For now, we assume the AI provided the full URL if it's a simple injection,
	// or we use the 'fill' action if we have a target element.
	
	return actionRes, nil
}
