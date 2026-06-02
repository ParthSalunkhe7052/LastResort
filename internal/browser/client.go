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

// NewClient instantiates a browser service HTTP client.
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = "http://localhost:3010"
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
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
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
