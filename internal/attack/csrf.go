package attack

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/parth/lastresort/internal/browser"
	"github.com/parth/lastresort/internal/gen/ai/v1/aiv1connect"
	"github.com/parth/lastresort/internal/scanner"
	"github.com/parth/lastresort/internal/storage"
)

// CsrfModule implements AttackModule for CSRF attacks.
type CsrfModule struct {
	aiClient aiv1connect.AiServiceClient
	scanID   string
}

func NewCsrfModule(aiClient aiv1connect.AiServiceClient, scanID string) *CsrfModule {
	return &CsrfModule{
		aiClient: aiClient,
		scanID:   scanID,
	}
}

func (m *CsrfModule) Name() string {
	return "Active Scan: CSRF"
}

func (m *CsrfModule) Plan(ctx context.Context, surf scanner.AttackSurface) ([]AttackAttempt, error) {
	log.Printf("[CSRF] Planning for surface: %s %s (IsForm: %v)", surf.Method, surf.URL, surf.IsForm)
	methodUpper := strings.ToUpper(surf.Method)
	if methodUpper != "POST" && methodUpper != "PUT" && methodUpper != "PATCH" && methodUpper != "DELETE" {
		return nil, nil
	}

	reqHeaders := make(http.Header)
	reqHeaders.Set("Content-Type", surf.ContentType)

	res, err := scanner.DetectCSRFHeuristic(surf.Method, surf.URL, reqHeaders, surf.BaseBody, surf.ContentType)
	if err != nil || res == nil || !res.Suspected {
		return nil, nil
	}

	return []AttackAttempt{
		{
			AttackType: "CSRF",
			URL:        surf.URL,
			Method:     surf.Method,
			Payload:    string(surf.BaseBody),
			Body:       surf.BaseBody,
			Headers:    map[string]string{"Content-Type": surf.ContentType, "Reason": res.Reason},
		},
	}, nil
}

func (m *CsrfModule) PlanAI(ctx context.Context, surf scanner.AttackSurface, baselineRes *browser.ActionResult) ([]AttackAttempt, string, error) {
	// CSRF doesn't currently benefit from AI payload generation as it's binary suspected/not suspected.
	return nil, "", nil
}

func (m *CsrfModule) Execute(ctx context.Context, executor BrowserExecutor, attempt AttackAttempt) (AttackResult, error) {
	log.Printf("[CSRF] Executing attack on: %s %s", attempt.Method, attempt.URL)
	methodUpper := strings.ToUpper(attempt.Method)

	// Execute Attack (deterministic browser execution)
	actionRes, err := executor.ExecuteAction(ctx, browser.ActionRequest{
		ScanID:    m.scanID,
		WorkerID:  "csrf",
		URL:       attempt.URL,
		Action:    "navigate", // We execute via evaluate/form submit script on navigate URL
	})

	if err == nil && actionRes != nil {
		script := makeFormSubmitScript(attempt.URL, methodUpper, attempt.Body)
		actionRes, err = executor.ExecuteAction(ctx, browser.ActionRequest{
			ScanID:    m.scanID,
			WorkerID:  "csrf",
			Action:    "evaluate",
			Value:     script,
		})
	}

	return AttackResult{
		Attempt:   attempt,
		RawResult: actionRes,
		Error:     err,
	}, nil
}

func (m *CsrfModule) Verify(ctx context.Context, res AttackResult, verifier Verifier) (*storage.VerificationResult, error) {
	if res.Error != nil || res.RawResult == nil {
		return &storage.VerificationResult{Verified: false}, nil
	}

	vr := verifier.VerifyCSRF(ctx, res.Attempt.URL, res.Attempt.Payload, res.RawResult.PageSource, res.RawResult.ScreenshotBase64)
	return vr, nil
}

func (m *CsrfModule) Record(ctx context.Context, recorder EvidenceRecorder, attempt AttackAttempt, result AttackResult, vr *storage.VerificationResult) (string, error) {
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
		AttackType:       "CSRF",
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
			Title:             fmt.Sprintf("CSRF - %s", attempt.URL),
			Description:       fmt.Sprintf("%s\n\nVerification: %s", attempt.Headers["Reason"], vr.EvidenceSummary),
			Severity:          "HIGH",
			VulnerabilityType: "CSRF",
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
