package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	connect "connectrpc.com/connect"
	aiv1 "github.com/parth/lastresort/internal/gen/ai/v1"
	"github.com/parth/lastresort/internal/storage"
)

type LocalServiceClient struct {
	httpClient *http.Client
	db         *storage.DB
}

func NewLocalServiceClient(db *storage.DB) *LocalServiceClient {
	return &LocalServiceClient{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		db: db,
	}
}

func (c *LocalServiceClient) getSettingOrEnv(ctx context.Context, key, envName string) string {
	if c.db != nil {
		val, err := c.db.GetSetting(ctx, key)
		if err == nil && val != "" {
			return val
		}
	}
	return os.Getenv(envName)
}

// Health checks the status of LLM keys and configurations
func (c *LocalServiceClient) Health(ctx context.Context, req *connect.Request[aiv1.HealthRequest]) (*connect.Response[aiv1.HealthResponse], error) {
	geminiKey := c.getSettingOrEnv(ctx, "gemini_api_key", "GEMINI_API_KEY")
	openRouterKey := c.getSettingOrEnv(ctx, "openrouter_api_key", "OPENROUTER_API_KEY")

	status := "offline"
	provider := "none"
	model := "none"
	initialized := false

	if c.db != nil {
		if p, err := c.db.GetSetting(ctx, "ai_provider"); err == nil && p != "" {
			provider = p
		}
		if m, err := c.db.GetSetting(ctx, "ai_model"); err == nil && m != "" {
			model = m
		}
	}

	if geminiKey != "" || openRouterKey != "" {
		status = "ok"
		initialized = true
		if provider == "none" {
			if geminiKey != "" {
				provider = "gemini"
			} else {
				provider = "openrouter"
			}
		}
		if model == "none" {
			if provider == "gemini" {
				model = "gemini-2.5-flash"
			} else {
				model = "openrouter/free"
			}
		}
	}

	return connect.NewResponse(&aiv1.HealthResponse{
		Status:      status,
		Provider:    provider,
		Model:       model,
		Initialized: initialized,
	}), nil
}

// CallLLM executes a text completion request with fallback logic (Gemini -> OpenRouter)
func (c *LocalServiceClient) CallLLM(ctx context.Context, prompt string, requireJSON bool) (string, error) {
	geminiKey := c.getSettingOrEnv(ctx, "gemini_api_key", "GEMINI_API_KEY")
	openRouterKey := c.getSettingOrEnv(ctx, "openrouter_api_key", "OPENROUTER_API_KEY")

	var lastErr error

	// 1. Try Gemini primary
	if geminiKey != "" {
		res, err := c.callGemini(ctx, geminiKey, prompt, requireJSON)
		if err == nil {
			return res, nil
		}
		log.Printf("[LLM] Primary Gemini key failed: %v", err)
		lastErr = err
	}

	// 2. Try Gemini backup keys
	backupKeysStr := c.getSettingOrEnv(ctx, "gemini_backup_keys", "GEMINI_BACKUP_KEYS")
	if backupKeysStr != "" {
		backupKeys := strings.Split(backupKeysStr, ",")
		for idx, bKey := range backupKeys {
			trimmed := strings.TrimSpace(bKey)
			if trimmed != "" {
				res, err := c.callGemini(ctx, trimmed, prompt, requireJSON)
				if err == nil {
					log.Printf("[LLM] Succeeded using backup Gemini key #%d", idx+1)
					return res, nil
				}
				log.Printf("[LLM] Backup Gemini key #%d failed: %v", idx+1, err)
				lastErr = err
			}
		}
	}

	// 3. Fallback to OpenRouter
	if openRouterKey != "" {
		res, err := c.callOpenRouter(ctx, openRouterKey, prompt, requireJSON)
		if err == nil {
			log.Printf("[LLM] Succeeded using OpenRouter fallback")
			return res, nil
		}
		log.Printf("[LLM] OpenRouter fallback failed: %v", err)
		lastErr = err
	}

	// 4. Try OpenRouter backup keys
	openRouterBackupStr := c.getSettingOrEnv(ctx, "openrouter_backup_keys", "OPENROUTER_BACKUP_KEYS")
	if openRouterBackupStr != "" {
		backupKeys := strings.Split(openRouterBackupStr, ",")
		for idx, bKey := range backupKeys {
			trimmed := strings.TrimSpace(bKey)
			if trimmed != "" {
				res, err := c.callOpenRouter(ctx, trimmed, prompt, requireJSON)
				if err == nil {
					log.Printf("[LLM] Succeeded using backup OpenRouter key #%d", idx+1)
					return res, nil
				}
				log.Printf("[LLM] Backup OpenRouter key #%d failed: %v", idx+1, err)
				lastErr = err
			}
		}
	}

	if lastErr != nil {
		return "", fmt.Errorf("all LLM keys exhausted. Last error: %w", lastErr)
	}
	return "", fmt.Errorf("no LLM keys configured (gemini_api_key or openrouter_api_key)")
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiRequest struct {
	Contents         []geminiContent `json:"contents"`
	GenerationConfig *generationConfig `json:"generationConfig,omitempty"`
}

type generationConfig struct {
	ResponseMimeType string `json:"responseMimeType"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func (c *LocalServiceClient) callGemini(ctx context.Context, apiKey, prompt string, requireJSON bool) (string, error) {
	model := "gemini-2.5-flash"
	if c.db != nil {
		if m, err := c.db.GetSetting(ctx, "ai_model"); err == nil && m != "" {
			model = m
		}
	}
	url := "https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent?key=" + apiKey

	reqData := geminiRequest{
		Contents: []geminiContent{
			{
				Parts: []geminiPart{
					{Text: prompt},
				},
			},
		},
	}

	if requireJSON {
		reqData.GenerationConfig = &generationConfig{
			ResponseMimeType: "application/json",
		}
	}

	bodyBytes, err := json.Marshal(reqData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini returned status %d: %s", resp.StatusCode, string(respBytes))
	}

	var geminiRes geminiResponse
	if err := json.Unmarshal(respBytes, &geminiRes); err != nil {
		return "", err
	}

	if len(geminiRes.Candidates) == 0 || len(geminiRes.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini returned empty response: %s", string(respBytes))
	}

	return geminiRes.Candidates[0].Content.Parts[0].Text, nil
}

type openRouterMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openRouterFormat struct {
	Type string `json:"type"`
}

type openRouterRequest struct {
	Model          string              `json:"model"`
	Messages       []openRouterMessage `json:"messages"`
	ResponseFormat *openRouterFormat   `json:"response_format,omitempty"`
}

type openRouterResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (c *LocalServiceClient) callOpenRouter(ctx context.Context, apiKey, prompt string, requireJSON bool) (string, error) {
	url := "https://openrouter.ai/api/v1/chat/completions"
	model := "openrouter/free"
	if c.db != nil {
		if m, err := c.db.GetSetting(ctx, "ai_model"); err == nil && m != "" {
			model = m
		}
	}

	reqData := openRouterRequest{
		Model: model,
		Messages: []openRouterMessage{
			{Role: "user", Content: prompt},
		},
	}

	if requireJSON {
		reqData.ResponseFormat = &openRouterFormat{Type: "json_object"}
	}

	bodyBytes, err := json.Marshal(reqData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openrouter returned status %d: %s", resp.StatusCode, string(respBytes))
	}

	var openRouterRes openRouterResponse
	if err := json.Unmarshal(respBytes, &openRouterRes); err != nil {
		return "", err
	}

	if len(openRouterRes.Choices) == 0 {
		return "", fmt.Errorf("openrouter returned empty response: %s", string(respBytes))
	}

	return openRouterRes.Choices[0].Message.Content, nil
}

// GenerateExecutiveSummary generates a summary of the scan results
func (c *LocalServiceClient) GenerateExecutiveSummary(ctx context.Context, req *connect.Request[aiv1.GenerateExecutiveSummaryRequest]) (*connect.Response[aiv1.GenerateExecutiveSummaryResponse], error) {
	findingsJSON, _ := json.Marshal(req.Msg.Findings)

	prompt := fmt.Sprintf(`
You are LastResort, an AI autonomous pentester reporting tool.
Please generate a brief, high-level executive summary report for a business founder / solo developer based on the following scan details:
Target URL: %s
Duration: %s
Detected Tech: %s
Severity Summary: Critical/High=%d, Medium=%d, Low=%d, Info=%d
Findings List:
%s

Your response must be in JSON format:
{
  "summary": "Clear, founder-friendly description of findings and risk profile.",
  "risk_rating": "Critical | High | Medium | Low | Safe",
  "key_recommendations": ["Recommendation 1", "Recommendation 2"]
}
`, req.Msg.TargetUrl, req.Msg.Duration, req.Msg.DetectedTechnologies, req.Msg.HighCount, req.Msg.MediumCount, req.Msg.LowCount, req.Msg.InfoCount, string(findingsJSON))

	resStr, err := c.CallLLM(ctx, prompt, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Parse JSON output
	var result struct {
		Summary            string   `json:"summary"`
		RiskRating         string   `json:"risk_rating"`
		KeyRecommendations []string `json:"key_recommendations"`
	}

	if err := json.Unmarshal([]byte(resStr), &result); err != nil {
		return connect.NewResponse(&aiv1.GenerateExecutiveSummaryResponse{
			Summary:            resStr,
			RiskRating:         "HIGH",
			KeyRecommendations: []string{"Review scan results and secure endpoints."},
		}), nil
	}

	return connect.NewResponse(&aiv1.GenerateExecutiveSummaryResponse{
		Summary:            result.Summary,
		RiskRating:         result.RiskRating,
		KeyRecommendations: result.KeyRecommendations,
	}), nil
}

// PlanAttack plans targeted attacks based on browser context and vulnerability type.
func (c *LocalServiceClient) PlanAttack(ctx context.Context, req *connect.Request[aiv1.PlanAttackRequest]) (*connect.Response[aiv1.PlanAttackResponse], error) {
	pageSource := req.Msg.CurrentContext.PageSource
	if len(pageSource) > 5000 {
		pageSource = pageSource[:5000] + "...[truncated]"
	}

	prompt := fmt.Sprintf(`
You are LastResort, an autonomous browser pentesting agent.
We are targeting %s vulnerabilities. We have extracted the following context:
URL: %s
Parameters: %v
DOM Content snippet:
%s

Analyze the structural context (Forms, Inputs, Action URLs, and DOM structure) to generate up to 5 smart, highly targeted payloads.
Tailor the payloads to the specific vulnerability type and the identified context.
Include your reasoning about the attack strategy.

Your response must be in JSON format matching this schema:
{
  "reasoning": "Technical reasoning based on context and vulnerability type",
  "payloads": [
    {
      "strategy": "Specific attack vector name",
      "value": "payload value here",
      "description": "Short explanation of why this payload fits this context"
    }
  ]
}
`, req.Msg.VulnerabilityType, req.Msg.Endpoint, req.Msg.Parameters, pageSource)

	resStr, err := c.CallLLM(ctx, prompt, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	var result struct {
		Reasoning string `json:"reasoning"`
		Payloads  []struct {
			Strategy    string `json:"strategy"`
			Value       string `json:"value"`
			Description string `json:"description"`
		} `json:"payloads"`
	}

	if err := json.Unmarshal([]byte(resStr), &result); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to parse AI payloads JSON: %w", err))
	}

	var payloads []*aiv1.AttackPayload
	for _, p := range result.Payloads {
		payloads = append(payloads, &aiv1.AttackPayload{
			Strategy:    p.Strategy,
			Value:       p.Value,
			Description: p.Description,
		})
	}

	return connect.NewResponse(&aiv1.PlanAttackResponse{
		Payloads:  payloads,
		Reasoning: result.Reasoning,
	}), nil
}

// VerifyAttackResult verifies if the payload successfully triggered an exploit.
func (c *LocalServiceClient) VerifyAttackResult(ctx context.Context, req *connect.Request[aiv1.VerifyAttackResultRequest]) (*connect.Response[aiv1.VerifyAttackResultResponse], error) {
	pageSourceExcerpt := req.Msg.Response.VisibleElements.PageSource
	if len(pageSourceExcerpt) > 4000 {
		pageSourceExcerpt = pageSourceExcerpt[:4000]
	}

	prompt := fmt.Sprintf(`
You are LastResort, a security verification engine.
We injected an attack payload: "%s".
The browser response is:
URL: %s
Title: %s
Status Code: %d
Page Source Excerpt:
%s

Did the exploit succeed? Be extremely skeptical.
- For SQL Injection: Look for database errors, login bypass indicators, or unexpected data leakage.
- For XSS: Look for evidence of script execution in the DOM (though usually handled by alert markers).
- For CSRF: Look for positive confirmation of the requested action succeeding despite missing tokens.
- For Path Traversal: Look for sensitive file contents (e.g. root:x:0:0).

Return JSON matching this schema:
{
  "confirmed": true/false,
  "reasoning": "Technical evidence-based reasoning. If not confirmed, explain why it looks sanitized or blocked.",
  "confidence": 0.0 to 1.0,
  "vulnerability_type": "The detected vulnerability type"
}
`, req.Msg.Payload, req.Msg.Response.CurrentUrl, req.Msg.Response.PageTitle, req.Msg.Response.StatusCode, pageSourceExcerpt)

	resStr, err := c.CallLLM(ctx, prompt, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	var result struct {
		Confirmed         bool    `json:"confirmed"`
		Reasoning         string  `json:"reasoning"`
		Confidence        float32 `json:"confidence"`
		VulnerabilityType string  `json:"vulnerability_type"`
	}

	if err := json.Unmarshal([]byte(resStr), &result); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to parse verification JSON: %w", err))
	}

	return connect.NewResponse(&aiv1.VerifyAttackResultResponse{
		Confirmed:         result.Confirmed,
		Reasoning:         result.Reasoning,
		Confidence:        result.Confidence,
		VulnerabilityType: result.VulnerabilityType,
	}), nil
}
