package attack

import (
	"context"
	"fmt"
	"strings"

	"github.com/parth/lastresort/internal/browser"
	"github.com/parth/lastresort/internal/gen/ai/v1/aiv1connect"
	"github.com/parth/lastresort/internal/scanner"
	"github.com/parth/lastresort/internal/storage"
)

// RateLimitModule implements AttackModule for Rate Limiting attacks.
type RateLimitModule struct {
	aiClient aiv1connect.AiServiceClient
	scanID   string
}

func NewRateLimitModule(aiClient aiv1connect.AiServiceClient, scanID string) *RateLimitModule {
	return &RateLimitModule{
		aiClient: aiClient,
		scanID:   scanID,
	}
}

func (m *RateLimitModule) Name() string {
	return "Active Scan: Rate Limiting"
}

func (m *RateLimitModule) Plan(ctx context.Context, surf scanner.AttackSurface) ([]AttackAttempt, error) {
	// Only plan for root endpoints or pages to avoid spamming sub-resource loads.
	if strings.Contains(surf.URL, ".js") || strings.Contains(surf.URL, ".css") || strings.Contains(surf.URL, ".png") {
		return nil, nil
	}

	return []AttackAttempt{
		{
			AttackType: "Rate Limiting",
			URL:        surf.URL,
			Method:     "GET",
			Payload:    "10 burst requests / 1s",
		},
	}, nil
}

func (m *RateLimitModule) PlanAI(ctx context.Context, surf scanner.AttackSurface, baselineRes *browser.ActionResult) ([]AttackAttempt, string, error) {
	return nil, "", nil
}

func (m *RateLimitModule) Execute(ctx context.Context, executor BrowserExecutor, attempt AttackAttempt) (AttackResult, error) {
	// controlled burst through Playwright fetch inside page context
	// Injects status list into lastresort-ratelimit-results DOM element
	script := fmt.Sprintf(`
		(async () => {
			const statuses = [];
			for (let i = 0; i < 10; i++) {
				try {
					const res = await fetch("%s", { cache: "no-store" });
					statuses.push(res.status);
				} catch (e) {
					statuses.push(0);
				}
				await newTime(50);
			}
			const div = document.createElement("div");
			div.id = "lastresort-ratelimit-results";
			div.setAttribute("data-statuses", statuses.join(","));
			document.body.appendChild(div);

			function newTime(ms) {
				return new Promise(resolve => setTimeout(resolve, ms));
			}
		})();
	`, attempt.URL)

	// First navigate to the page
	actionRes, err := executor.ExecuteAction(ctx, browser.ActionRequest{
		ScanID:   m.scanID,
		WorkerID: "ratelimit",
		URL:      attempt.URL,
		Action:   "navigate",
	})

	if err == nil && actionRes != nil {
		actionRes, err = executor.ExecuteAction(ctx, browser.ActionRequest{
			ScanID:   m.scanID,
			WorkerID: "ratelimit",
			Action:   "evaluate",
			Value:    script,
		})
		if err == nil && actionRes != nil {
			// Wait 1 second for the async fetches inside Playwright to complete
			actionRes, err = executor.ExecuteAction(ctx, browser.ActionRequest{
				ScanID:   m.scanID,
				WorkerID: "ratelimit",
				Action:   "wait",
				Value:    "1000",
			})
		}
	}

	return AttackResult{
		Attempt:   attempt,
		RawResult: actionRes,
		Error:     err,
	}, nil
}

func (m *RateLimitModule) Verify(ctx context.Context, res AttackResult, verifier Verifier) (*storage.VerificationResult, error) {
	if res.Error != nil || res.RawResult == nil {
		return &storage.VerificationResult{Verified: false}, nil
	}

	vr := verifier.VerifyRateLimit(ctx, res.Attempt.URL, res.RawResult.PageSource, res.RawResult.ScreenshotBase64)
	return vr, nil
}

func (m *RateLimitModule) Record(ctx context.Context, recorder EvidenceRecorder, attempt AttackAttempt, result AttackResult, vr *storage.VerificationResult) (string, error) {
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
		AttackType:       "Rate Limiting",
		Endpoint:         attempt.URL,
		Payload:          attempt.Payload,
		RequestCaptured:  fmt.Sprintf("%s %s\nPayload: %s", attempt.Method, attempt.URL, attempt.Payload),
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
			Title:             "Missing Rate Limiting Protection",
			Description:       fmt.Sprintf("Missing Rate Limiting Protection verified by agent analysis.\n\nEvidence: %s", vr.EvidenceSummary),
			Severity:          "INFO",
			VulnerabilityType: "Rate Limit Testing",
			Endpoint:          attempt.URL,
			Payload:           attempt.Payload,
			ResponseStatus:    200,
			Confidence:        vr.Confidence,
			Category:          storage.StatePotentialFinding,
		}, storage.EvidenceInput{
			FlowID:          0,
			EvidenceType:    storage.EvidenceTiming,
			RequestExcerpt:  fmt.Sprintf("GET %s (10 rapid requests)", attempt.URL),
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
