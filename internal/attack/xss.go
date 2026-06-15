package attack

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/parth/lastresort/internal/browser"
	aiv1 "github.com/parth/lastresort/internal/gen/ai/v1"
	"github.com/parth/lastresort/internal/gen/ai/v1/aiv1connect"
	"github.com/parth/lastresort/internal/scanner"
	"github.com/parth/lastresort/internal/storage"
)

// XSSModule implements AttackModule for Cross-Site Scripting attacks.
type XSSModule struct {
	aiClient aiv1connect.AiServiceClient
	scanID   string
}

func NewXSSModule(aiClient aiv1connect.AiServiceClient, scanID string) *XSSModule {
	return &XSSModule{
		aiClient: aiClient,
		scanID:   scanID,
	}
}

func (m *XSSModule) Name() string {
	return "Active Scan: XSS"
}

func (m *XSSModule) Plan(ctx context.Context, surf scanner.AttackSurface) ([]AttackAttempt, error) {
	var attempts []AttackAttempt

	for _, payload := range scanner.XSSPayloads {
		injectedURL, injectedBody := scanner.BuildInjectedRequest(surf.Method, surf.URL, surf.BaseBody, surf.ContentType, surf.Point, payload.Value)
		attempts = append(attempts, AttackAttempt{
			AttackType: "XSS",
			URL:        injectedURL,
			Method:     surf.Method,
			Payload:    payload.Value,
			Body:       injectedBody,
			Headers:    map[string]string{"Content-Type": surf.ContentType},
		})
	}

	return attempts, nil
}

func (m *XSSModule) PlanAI(ctx context.Context, surf scanner.AttackSurface, baselineRes *browser.ActionResult) ([]AttackAttempt, string, error) {
	if m.aiClient == nil {
		return nil, "", nil
	}

	resp, err := m.aiClient.PlanAttack(ctx, connect.NewRequest(&aiv1.PlanAttackRequest{
		VulnerabilityType: "XSS",
		CurrentContext:    ConvertToProtoContext(baselineRes),
		Endpoint:          surf.URL,
		Parameters:        []string{surf.Point.Name},
	}))
	if err != nil {
		return nil, "", err
	}

	var attempts []AttackAttempt
	for _, payload := range resp.Msg.Payloads {
		injectedURL, injectedBody := scanner.BuildInjectedRequest(surf.Method, surf.URL, surf.BaseBody, surf.ContentType, surf.Point, payload.Value)
		attempts = append(attempts, AttackAttempt{
			AttackType: "XSS",
			URL:        injectedURL,
			Method:     surf.Method,
			Payload:    payload.Value,
			Body:       injectedBody,
			Headers:    map[string]string{"Content-Type": surf.ContentType},
		})
	}

	return attempts, resp.Msg.Reasoning, nil
}

func (m *XSSModule) Execute(ctx context.Context, executor BrowserExecutor, attempt AttackAttempt) (AttackResult, error) {
	methodUpper := strings.ToUpper(attempt.Method)
	var actionRes *browser.ActionResult
	var err error

	if methodUpper == "GET" || len(attempt.Body) == 0 {
		actionRes, err = executor.ExecuteAction(ctx, browser.ActionRequest{
			ScanID:   m.scanID,
			WorkerID: "xss",
			URL:      attempt.URL,
			Action:   "navigate",
		})
	} else {
		script := makeFormSubmitScript(attempt.URL, methodUpper, attempt.Body)
		actionRes, err = executor.ExecuteAction(ctx, browser.ActionRequest{
			ScanID:   m.scanID,
			WorkerID: "xss",
			Action:   "evaluate",
			Value:    script,
		})
	}

	return AttackResult{
		Attempt:   attempt,
		RawResult: actionRes,
		Error:     err,
	}, nil
}

func (m *XSSModule) Verify(ctx context.Context, res AttackResult, verifier Verifier) (*storage.VerificationResult, error) {
	if res.Error != nil || res.RawResult == nil {
		return &storage.VerificationResult{Verified: false}, nil
	}

	vr := verifier.VerifyXSS(ctx, "Reflected XSS", res.Attempt.URL, res.Attempt.Payload, res.RawResult.PageSource, res.RawResult.ScreenshotBase64)
	return vr, nil
}

func (m *XSSModule) Record(ctx context.Context, recorder EvidenceRecorder, attempt AttackAttempt, result AttackResult, vr *storage.VerificationResult) (string, error) {
	_ = recorder.IncrementAttackExecuted(ctx, m.scanID)

	responseCaptured := ""
	if result.RawResult != nil && result.RawResult.PageSource != "" {
		responseCaptured = result.RawResult.PageSource
		if len(responseCaptured) > 1000 {
			responseCaptured = responseCaptured[:1000]
		}
	}

	attemptID, _ := recorder.SaveAttackAttempt(ctx, storage.AttackAttemptInput{
		ScanID:           m.scanID,
		AttackType:       "XSS",
		Endpoint:         attempt.URL,
		Payload:          attempt.Payload,
		RequestCaptured:  fmt.Sprintf("%s %s\nContent-Type: %s\n\n%s", attempt.Method, attempt.URL, attempt.Headers["Content-Type"], string(attempt.Body)),
		ResponseCaptured: responseCaptured,
		EvidenceFound:    vr.EvidenceSummary,
		Result:           "failed",
	})

	if vr.Verified {
		_ = recorder.IncrementAttackVerified(ctx, m.scanID)
		if attemptID != "" {
			if db, ok := recorder.(*storage.DB); ok {
				_, _ = db.ExecContext(ctx, "UPDATE attack_attempts SET result = ?, evidence_found = ? WHERE id = ?", "verified", vr.EvidenceSummary, attemptID)
			}
		}

		findingID, err := recorder.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            m.scanID,
			Title:             fmt.Sprintf("XSS - %s", attempt.Payload),
			Description:       fmt.Sprintf("Reflected Cross-Site Scripting vulnerability verified by agent analysis.\n\nEvidence: %s", vr.EvidenceSummary),
			Severity:          "HIGH",
			VulnerabilityType: "XSS",
			Endpoint:          attempt.URL,
			Payload:           attempt.Payload,
			ResponseStatus:    200,
			Confidence:        vr.Confidence,
			Category:          storage.StatePotentialFinding,
		}, storage.EvidenceInput{
			FlowID:          0,
			EvidenceType:    storage.EvidenceScreenshot,
			RequestExcerpt:  fmt.Sprintf("%s %s\nPayload: %s", attempt.Method, attempt.URL, attempt.Payload),
			ResponseExcerpt: responseCaptured,
			ScreenshotB64:   result.RawResult.ScreenshotBase64,
		})
		if err != nil {
			return "", err
		}

		verifID, err := recorder.SaveVerification(ctx, findingID, m.scanID, vr)
		if err == nil && verifID != "" {
			if db, ok := recorder.(*storage.DB); ok {
				_, _ = db.ExecContext(ctx, "UPDATE findings SET category = ?, verification_id = ? WHERE id = ?", storage.StateVerifiedFinding, verifID, findingID)
			}
		}
		return findingID, nil
	}

	_ = recorder.IncrementAttackFailed(ctx, m.scanID)
	return "", nil
}
