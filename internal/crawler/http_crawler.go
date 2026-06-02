package crawler

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// DiscoveredEndpoint represents a route discovered by the crawler
type DiscoveredEndpoint struct {
	Method string
	URL    string
	Source string // e.g. "robots", "sitemap", "crawler", "js_analyzer"
}

// CrawlSession manages the state of an active crawl
type CrawlSession struct {
	ScanID     string
	SeedURL    string
	SeedHost   string
	Client     *http.Client
	MaxDepth   int
	Visited    sync.Map
	Endpoints  chan DiscoveredEndpoint
	ErrorLogs  chan string
	CancelFunc context.CancelFunc
}

type proxyRoundTripper struct {
	scanID string
	base   http.RoundTripper
}

func (p *proxyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("X-LastResort-Scan-ID", p.scanID)
	req.Header.Set("User-Agent", "LastResort-Crawler/0.1.0")
	return p.base.RoundTrip(req)
}

// GetCrawlClient builds an http.Client. It attempts to route through the local proxy
// at localhost:proxyPort, falling back to a direct client if the proxy is unavailable.
func GetCrawlClient(scanID string, proxyPort int) *http.Client {
	if proxyPort <= 0 {
		proxyPort = 8080
	}
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	conn, err := net.DialTimeout("tcp", proxyAddr, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		// Proxy is running, use it
		proxyURL, _ := url.Parse("http://" + proxyAddr)
		transport := &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		return &http.Client{
			Transport: &proxyRoundTripper{
				scanID: scanID,
				base:   transport,
			},
			Timeout: 8 * time.Second,
		}
	}

	// Fallback to direct client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Transport: &proxyRoundTripper{
			scanID: scanID,
			base:   transport,
		},
		Timeout: 8 * time.Second,
	}
}

// CrawlPage fetches a URL and parses its HTML links, forms, and scripts.
func CrawlPage(ctx context.Context, session *CrawlSession, targetURL string, depth int) ([]string, []string) {
	// Skip if already visited
	if _, loaded := session.Visited.LoadOrStore(targetURL, true); loaded {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, nil
	}

	resp, err := session.Client.Do(req)
	if err != nil {
		session.ErrorLogs <- fmt.Sprintf("Failed to fetch %s: %v", targetURL, err)
		return nil, nil
	}
	defer resp.Body.Close()

	// Notify proxy/dashboard of this endpoint
	session.Endpoints <- DiscoveredEndpoint{
		Method: "GET",
		URL:    targetURL,
		Source: "crawler",
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	// We only parse links from HTML responses
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		return nil, nil
	}

	return parseHTML(resp.Body, targetURL)
}

// parseHTML parses the HTML reader and extracts links, form destinations, and scripts.
func parseHTML(body io.Reader, baseURL string) ([]string, []string) {
	var nextURLs []string
	var jsURLs []string

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return nil, nil
	}

	tokenizer := html.NewTokenizer(body)
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}

		switch tokenType {
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			
			// 1. Anchor links
			if token.Data == "a" {
				for _, attr := range token.Attr {
					if attr.Key == "href" {
						val := strings.TrimSpace(attr.Val)
						if val == "" || strings.HasPrefix(val, "#") || strings.HasPrefix(val, "javascript:") {
							continue
						}
						
						resolved := resolveURL(parsedBase, val)
						if resolved != "" {
							nextURLs = append(nextURLs, resolved)
						}
					}
				}
			}

			// 2. Form actions
			if token.Data == "form" {
				for _, attr := range token.Attr {
					if attr.Key == "action" {
						val := strings.TrimSpace(attr.Val)
						resolved := resolveURL(parsedBase, val)
						if resolved != "" {
							nextURLs = append(nextURLs, resolved)
						}
					}
				}
			}

			// 3. Script sources (JS Analyzer inputs)
			if token.Data == "script" {
				for _, attr := range token.Attr {
					if attr.Key == "src" {
						val := strings.TrimSpace(attr.Val)
						if val != "" {
							resolved := resolveURL(parsedBase, val)
							if resolved != "" {
								jsURLs = append(jsURLs, resolved)
							}
						}
					}
				}
			}
		}
	}

	return nextURLs, jsURLs
}

func resolveURL(base *url.URL, ref string) string {
	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(refURL)
	return resolved.String()
}

// IsInCrawlScope checks if targetURL belongs to the same host as seedHost.
func IsInCrawlScope(targetURL, seedHost string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	return u.Host == seedHost
}
