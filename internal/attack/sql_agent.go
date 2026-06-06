package attack

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/parth/lastresort/internal/browser"
	aiv1 "github.com/parth/lastresort/internal/gen/ai/v1"
	"github.com/parth/lastresort/internal/gen/ai/v1/aiv1connect"
	"github.com/parth/lastresort/internal/storage"
	"github.com/parth/lastresort/internal/scanner"
	"connectrpc.com/connect"
)

// AgentSQLiExecutor coordinates SQLi attack planning, execution, and verification.
type AgentSQLiExecutor struct {
	db           *storage.DB
	browser      *browser.Client
	aiClient     aiv1connect.AiServiceClient
	scanID       string
	proxyPort    int
	onLog        func(string)
	screenshotFn func(string)
}

func NewAgentSQLiExecutor(db *storage.DB, browserClient *browser.Client, aiClient aiv1connect.AiServiceClient, scanID string, proxyPort int, onLog func(string), screenshotFn func(string)) *AgentSQLiExecutor {
	return &AgentSQLiExecutor{
		db:           db,
		browser:      browserClient,
		aiClient:     aiClient,
		scanID:       scanID,
		proxyPort:    proxyPort,
		onLog:        onLog,
		screenshotFn: screenshotFn,
	}
}

// executePayloadViaBrowser navigates to or submits a form with a given SQLi payload.
func (e *AgentSQLiExecutor) executePayloadViaBrowser(ctx context.Context, method, urlStr string, body []byte, formPageURL string) (*browser.ActionResult, error) {
	methodUpper := strings.ToUpper(method)
	if methodUpper == "GET" || len(body) == 0 {
		actionReq := browser.ActionRequest{
			ScanID:    e.scanID,
			WorkerID:  "sqli_agent",
			URL:       urlStr,
			Action:    "navigate",
			ProxyPort: e.proxyPort,
		}
		res, err := e.browser.ExecuteAction(ctx, actionReq)
		if err == nil && res != nil && res.ScreenshotBase64 != "" && e.screenshotFn != nil {
			e.screenshotFn(res.ScreenshotBase64)
		}
		return res, err
	}

	navigateURL := urlStr
	if formPageURL != "" {
		navigateURL = formPageURL
	}

	navRes, _ := e.browser.ExecuteAction(ctx, browser.ActionRequest{
		ScanID:    e.scanID,
		WorkerID:  "sqli_agent",
		URL:       navigateURL,
		Action:    "navigate",
		ProxyPort: e.proxyPort,
	})
	if navRes != nil && navRes.ScreenshotBase64 != "" && e.screenshotFn != nil {
		e.screenshotFn(navRes.ScreenshotBase64)
	}

	script := makeFormSubmitScript(urlStr, methodUpper, body)
	actionReq := browser.ActionRequest{
		ScanID:    e.scanID,
		WorkerID:  "sqli_agent",
		Action:    "evaluate",
		Value:     script,
		ProxyPort: e.proxyPort,
	}
	res, err := e.browser.ExecuteAction(ctx, actionReq)
	if err == nil && res != nil && res.ScreenshotBase64 != "" && e.screenshotFn != nil {
		e.screenshotFn(res.ScreenshotBase64)
	}
	return res, err
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

// ConvertToProtoContext serializes Go browser structures to Protobuf messages
func ConvertToProtoContext(target *browser.ActionResult) *aiv1.BrowserContext {
	if target == nil {
		return &aiv1.BrowserContext{}
	}

	forms := make([]*aiv1.BrowserForm, len(target.Forms))
	for i, f := range target.Forms {
		inputs := make([]*aiv1.BrowserElement, len(f.Inputs))
		for j, in := range f.Inputs {
			inputs[j] = &aiv1.BrowserElement{
				Text:     in.Text,
				Selector: in.Selector,
				Type:     in.Type,
				Href:     in.Href,
				Id:       in.ID,
				Name:     in.Name,
				Value:    in.Value,
			}
		}
		forms[i] = &aiv1.BrowserForm{
			Selector: f.Selector,
			Action:   f.Action,
			Method:   f.Method,
			Inputs:   inputs,
		}
	}

	inputs := make([]*aiv1.BrowserElement, len(target.Links)) 
	buttons := make([]*aiv1.BrowserElement, len(target.Buttons))
	for i, b := range target.Buttons {
		buttons[i] = &aiv1.BrowserElement{
			Text:     b.Text,
			Selector: b.Selector,
			Type:     b.Type,
			Id:       b.ID,
			Name:     b.Name,
			Value:    b.Value,
		}
	}

	links := make([]*aiv1.BrowserElement, len(target.Links))
	for i, l := range target.Links {
		links[i] = &aiv1.BrowserElement{
			Text:     l.Text,
			Selector: l.Selector,
			Type:     l.Type,
			Href:     l.Href,
			Id:       l.ID,
			Name:     l.Name,
			Value:    l.Value,
		}
	}

	cookies := make(map[string]string)
	for _, c := range target.Cookies {
		cookies[c.Name] = c.Value
	}

	return &aiv1.BrowserContext{
		CurrentUrl:   target.CurrentURL,
		PageTitle:    target.PageTitle,
		PageSource:   target.PageSource,
		Screenshot:   target.ScreenshotBase64,
		Cookies:      cookies,
		LocalStorage: target.LocalStorage,
		Forms:        forms,
		Inputs:       inputs,
		Buttons:      buttons,
		Links:        links,
	}
}

func ConvertToProtoActionResult(res *browser.ActionResult) *aiv1.ActionResult {
	if res == nil {
		return &aiv1.ActionResult{}
	}

	events := make([]*aiv1.NetworkEvent, len(res.NetworkEvents))
	for i, ev := range res.NetworkEvents {
		events[i] = &aiv1.NetworkEvent{
			Method:       ev.Method,
			Url:          ev.URL,
			StatusCode:   int32(ev.StatusCode),
			ResourceType: ev.ResourceType,
		}
	}

	return &aiv1.ActionResult{
		Success:         res.Success,
		FailureReason:   res.FailureReason,
		CurrentUrl:      res.CurrentURL,
		PageTitle:       res.PageTitle,
		Screenshot:      res.ScreenshotBase64,
		VisibleElements: ConvertToProtoContext(res),
		NetworkEvents:   events,
	}
}

func (e *AgentSQLiExecutor) Execute(ctx context.Context, surf scanner.AttackSurface) error {
	e.onLog(fmt.Sprintf("[AGENT] SQLi attack started for: %s %s (parameter: %s)", surf.Method, surf.URL, surf.Point.Name))

	// Phase 1: Static Payloads
	for _, payload := range scanner.SQLiPayloads {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := e.executeAndVerifyPayload(ctx, surf, payload.Value, fmt.Sprintf("Static (%s)", payload.Strategy), "Deterministic rule-set"); err != nil {
			if strings.Contains(err.Error(), "EXPLOIT_SUCCESS") {
				return nil
			}
		}
	}

	// Phase 2: AI-Planned Payloads
	actionRes, err := e.executePayloadViaBrowser(ctx, surf.Method, surf.URL, surf.BaseBody, surf.FormPageURL)
	if err != nil {
		return fmt.Errorf("baseline request failed: %w", err)
	}

	resp, err := e.aiClient.PlanSQLiAttack(ctx, connect.NewRequest(&aiv1.PlanSQLiAttackRequest{
		CurrentContext: ConvertToProtoContext(actionRes),
		Endpoint:       surf.URL,
		Parameters:     []string{surf.Point.Name},
	}))
	if err != nil {
		return fmt.Errorf("AI planning failed: %w", err)
	}

	e.onLog(fmt.Sprintf("[AGENT] AI planned %d payloads. Reasoning: %s", len(resp.Msg.Payloads), resp.Msg.Reasoning))

	for _, payload := range resp.Msg.Payloads {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := e.executeAndVerifyPayload(ctx, surf, payload.Value, fmt.Sprintf("AI (%s)", payload.Strategy), resp.Msg.Reasoning); err != nil {
			if strings.Contains(err.Error(), "EXPLOIT_SUCCESS") {
				return nil
			}
		}
	}

	return nil
	}

	func (e *AgentSQLiExecutor) executeAndVerifyPayload(ctx context.Context, surf scanner.AttackSurface, payloadValue, strategy, reasoning string) error {
	e.onLog(fmt.Sprintf("[AGENT] Executing SQLi: %s (%s)", payloadValue, strategy))
	_ = e.db.IncrementAttackExecuted(ctx, e.scanID)

	injectedURL, injectedBody := scanner.BuildInjectedRequest(surf.Method, surf.URL, surf.BaseBody, surf.ContentType, surf.Point, payloadValue)

	attemptID, _ := e.db.SaveAttackAttempt(ctx, storage.AttackAttemptInput{
		ScanID:           e.scanID,
		AttackType:       "SQL Injection",
		Endpoint:         injectedURL,
		Payload:          payloadValue,
		RequestCaptured:  fmt.Sprintf("%s %s\nContent-Type: %s\n\n%s", surf.Method, injectedURL, surf.ContentType, string(injectedBody)),
		ResponseCaptured: "",
		EvidenceFound:    "",
		Result:           "failed",
	})

	result, err := e.executePayloadViaBrowser(ctx, surf.Method, injectedURL, injectedBody, surf.FormPageURL)
	if err != nil || result == nil {
		_ = e.db.IncrementAttackFailed(ctx, e.scanID)
		return nil
	}

	if attemptID != "" && result.PageSource != "" {
		resExcerpt := result.PageSource
		if len(resExcerpt) > 1000 {
			resExcerpt = resExcerpt[:1000]
		}
		_, _ = e.db.ExecContext(ctx, "UPDATE attack_attempts SET response_captured = ? WHERE id = ?", resExcerpt, attemptID)
	}

	step, _ := e.db.GetLastJournalStep(ctx, e.scanID)
	_ = e.db.SaveJournalEntry(ctx, &storage.JournalEntry{
		ScanID:    e.scanID,
		Step:      step + 1,
		Action:    "sqli_test",
		Selector:  surf.Point.Name,
		Value:     payloadValue,
		Success:   result.Success,
		Error:     result.FailureReason,
		Reasoning: reasoning,
		Result:    result,
	})

	if e.aiClient != nil {
		verifyResp, err := e.aiClient.VerifyAttackResult(ctx, connect.NewRequest(&aiv1.VerifyAttackResultRequest{
			Payload:  payloadValue,
			Response: ConvertToProtoActionResult(result),
		}))
		if err == nil && verifyResp != nil && verifyResp.Msg.Confirmed {
			e.onLog(fmt.Sprintf("[AGENT] EXPLOIT SUCCESSFUL! AI verified SQLi: %s", verifyResp.Msg.Reasoning))
			_, _ = e.db.ExecContext(ctx, "UPDATE attack_attempts SET result = ?, evidence_found = ? WHERE id = ?", "verified", verifyResp.Msg.Reasoning, attemptID)
			_ = e.saveAgentFinding(ctx, surf, payloadValue, result, verifyResp.Msg.Reasoning, float64(verifyResp.Msg.Confidence))
			return fmt.Errorf("EXPLOIT_SUCCESS")
		}
	}

	dvr := scanner.VerifySQLiDeterministic(surf.URL, payloadValue, result.PageSource, result.ScreenshotBase64)
	if dvr.Verified {
		e.onLog(fmt.Sprintf("[AGENT] EXPLOIT SUCCESSFUL! Deterministic verification confirmed SQLi: %s", dvr.EvidenceSummary))
		_, _ = e.db.ExecContext(ctx, "UPDATE attack_attempts SET result = ?, evidence_found = ? WHERE id = ?", "verified", dvr.EvidenceSummary, attemptID)
		_ = e.saveAgentFinding(ctx, surf, payloadValue, result, dvr.EvidenceSummary, dvr.Confidence)
		return fmt.Errorf("EXPLOIT_SUCCESS")
	}

	_ = e.db.IncrementAttackFailed(ctx, e.scanID)
	return nil
	}


func (e *AgentSQLiExecutor) saveAgentFinding(ctx context.Context, surf scanner.AttackSurface, payload string, result *browser.ActionResult, evidence string, confidence float64) error {
	_ = e.db.IncrementAttackVerified(ctx, e.scanID)

	findingID, err := e.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
		ScanID:            e.scanID,
		Title:             fmt.Sprintf("SQL Injection (Agent-Verified) - %s", surf.Point.Name),
		Description:       fmt.Sprintf("SQL Injection vulnerability verified by agent analysis.\n\nEvidence: %s", evidence),
		Severity:          "CRITICAL",
		VulnerabilityType: "SQL Injection",
		Endpoint:          surf.URL,
		Payload:           payload,
		ResponseStatus:    200,
		Confidence:        confidence,
		Category:          storage.StatePotentialFinding,
	}, storage.EvidenceInput{
		FlowID:          0,
		EvidenceType:    storage.EvidenceScreenshot,
		RequestExcerpt:  fmt.Sprintf("%s %s\nParameter: %s\nPayload: %s", surf.Method, surf.URL, surf.Point.Name, payload),
		ResponseExcerpt: result.PageSource,
		ScreenshotB64:   result.ScreenshotBase64,
	})

	if err == nil {
		vr := &storage.VerificationResult{
			EndpointURL:     surf.URL,
			Payload:         payload,
			VerifiedAt:      time.Now(),
			Verified:        true,
			Confidence:      confidence,
			Method:          storage.VerificationAIScored,
			EvidenceSummary: evidence,
		}
		verifID, verifErr := e.db.SaveVerification(ctx, findingID, e.scanID, vr)
		if verifErr == nil {
			if _, updateErr := e.db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID); updateErr != nil {
				e.onLog(fmt.Sprintf("[ERROR] Failed to update finding category: %v", updateErr))
			}
		} else {
			e.onLog(fmt.Sprintf("[ERROR] Failed to save verification: %v", verifErr))
		}
	} else {
		e.onLog(fmt.Sprintf("[ERROR] Failed to save finding: %v", err))
	}
	return nil
}
