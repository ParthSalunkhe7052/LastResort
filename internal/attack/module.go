package attack

import (
	"context"
	"fmt"
	"net/url"

	"github.com/parth/lastresort/internal/browser"
	aiv1 "github.com/parth/lastresort/internal/gen/ai/v1"
	"github.com/parth/lastresort/internal/scanner"
	"github.com/parth/lastresort/internal/storage"
)

// AttackAttempt represents a specific fuzzing/exploit command to be sent to a target.
type AttackAttempt struct {
	ID         string
	AttackType string
	URL        string
	Method     string
	Payload    string
	Body       []byte
	Headers    map[string]string
}

// AttackResult encapsulates the outputs captured from browser execution of an attempt.
type AttackResult struct {
	Attempt   AttackAttempt
	RawResult *browser.ActionResult
	Error     error
}

// AttackModule defines the lifecycle of a vulnerability scanning module.
type AttackModule interface {
	Name() string
	Plan(ctx context.Context, surface scanner.AttackSurface) ([]AttackAttempt, error)
	Execute(ctx context.Context, executor BrowserExecutor, attempt AttackAttempt) (AttackResult, error)
	Verify(ctx context.Context, result AttackResult, verifier Verifier) (*storage.VerificationResult, error)
	Record(ctx context.Context, recorder EvidenceRecorder, attempt AttackAttempt, result AttackResult, vr *storage.VerificationResult) (string, error)
}

// BrowserExecutor abstracts execution of network requests and actions through the Playwright browser context.
type BrowserExecutor interface {
	ExecuteAction(ctx context.Context, req browser.ActionRequest) (*browser.ActionResult, error)
}

// Verifier abstracts logical analysis of attack results (using heuristics or AI verification).
type Verifier interface {
	VerifyXSS(ctx context.Context, vulnType, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult
	VerifySQLi(ctx context.Context, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult
	VerifyCSRF(ctx context.Context, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult
	VerifyPathTraversal(ctx context.Context, endpoint, payload, pageSource, screenshotB64 string) *storage.VerificationResult
	VerifyRateLimit(ctx context.Context, endpoint, pageSource, screenshotB64 string) *storage.VerificationResult
}

// EvidenceRecorder abstracts the database operations needed to persist scan discoveries.
type EvidenceRecorder interface {
	SaveAttackAttempt(ctx context.Context, in storage.AttackAttemptInput) (string, error)
	SaveFindingWithEvidence(ctx context.Context, in storage.FindingInput, ev storage.EvidenceInput) (string, error)
	SaveVerification(ctx context.Context, findingID, scanID string, vr *storage.VerificationResult) (string, error)
	IncrementAttackExecuted(ctx context.Context, scanID string) error
	IncrementAttackFailed(ctx context.Context, scanID string) error
	IncrementAttackVerified(ctx context.Context, scanID string) error
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

	links := make([]*aiv1.BrowserElement, len(target.Links)) 
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
		Inputs:       nil,
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
