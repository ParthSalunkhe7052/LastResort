package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client communicates with the Playwright browser crawler service.
type Client struct {
	baseURL string
	client  *http.Client
}

// DiscoveredEndpoint represents a route discovered by the browser crawler.
type DiscoveredEndpoint struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

// CrawlRequest is the body format expected by the browser crawler.
type CrawlRequest struct {
	ScanID    string `json:"scanId"`
	TargetURL string `json:"targetUrl"`
	ProxyPort int    `json:"proxyPort"`
}

// CrawlResponse is the format returned by the browser crawler.
type CrawlResponse struct {
	Success   bool                 `json:"success"`
	Endpoints []DiscoveredEndpoint `json:"endpoints"`
	Error     string               `json:"error"`
}

// ActionRequest is the body format for browser interaction commands.
type ActionRequest struct {
	ScanID    string `json:"scanId"`
	URL       string `json:"url"`
	Action    string `json:"action"`    // "click", "fill", "type", "navigate"
	Selector  string `json:"selector"`  // CSS selector
	Value     string `json:"value"`     // text to fill/type
	ProxyPort int    `json:"proxyPort"`
}

type ActionResponse struct {
	Success    bool   `json:"success"`
	Screenshot string `json:"screenshot"` // base64
	PageSource string `json:"pageSource"`
	Error      string `json:"error"`
}

// NewClient instantiates a browser service HTTP client.
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = "http://127.0.0.1:3010"
	}
	return &Client{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 5 * time.Minute, // browser crawling can be slow
		},
	}
}

// IsOnline checks if the browser crawler service is running.
func (c *Client) IsOnline(ctx context.Context) bool {
	healthCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(healthCtx, "GET", c.baseURL+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Crawl sends a crawl request to the Playwright service.
func (c *Client) Crawl(ctx context.Context, scanID, targetURL string, proxyPort int) ([]DiscoveredEndpoint, error) {
	reqBody, err := json.Marshal(CrawlRequest{
		ScanID:    scanID,
		TargetURL: targetURL,
		ProxyPort: proxyPort,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/crawl", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to contact browser service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("browser service returned non-200 status code: %d", resp.StatusCode)
	}

	var crawlResp CrawlResponse
	if err := json.NewDecoder(resp.Body).Decode(&crawlResp); err != nil {
		return nil, fmt.Errorf("failed to decode browser crawl response: %w", err)
	}

	if !crawlResp.Success {
		return nil, fmt.Errorf("browser crawl failed: %s", crawlResp.Error)
	}

	return crawlResp.Endpoints, nil
}

// ExecuteAction sends a single browser interaction command to the Playwright service.
func (c *Client) ExecuteAction(ctx context.Context, req ActionRequest) (*ActionResponse, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal action request: %w", err)
	}

	hReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/action", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create action request: %w", err)
	}
	hReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(hReq)
	if err != nil {
		return nil, fmt.Errorf("failed to contact browser service for action: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("browser service action returned non-200 status code: %d", resp.StatusCode)
	}

	var actionResp ActionResponse
	if err := json.NewDecoder(resp.Body).Decode(&actionResp); err != nil {
		return nil, fmt.Errorf("failed to decode browser action response: %w", err)
	}

	return &actionResp, nil
}

