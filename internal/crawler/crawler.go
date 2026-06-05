package crawler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/parth/lastresort/internal/browser"
	"github.com/parth/lastresort/internal/attack"
)

// CrawlManager orchestrates sitemap parsing, link crawling, and JS analysis.
type CrawlManager struct {
	client    *http.Client
	proxyPort int
}

// NewCrawlManager creates a new CrawlManager.
func NewCrawlManager(scanID string, proxyPort int) *CrawlManager {
	return &CrawlManager{
		client:    GetCrawlClient(scanID, proxyPort),
		proxyPort: proxyPort,
	}
}

// Crawl executes the complete crawl phase for a target URL.
// It uses a callback function to send discovery logs back to the orchestrator.
func (cm *CrawlManager) Crawl(ctx context.Context, scanID, seedURL string, onLog func(msg string), onEndpoint func(method, urlStr, source string), onForm func(form browser.DiscoveredForm)) error {
	u, err := url.Parse(seedURL)
	if err != nil {
		return fmt.Errorf("invalid seed URL: %w", err)
	}
	seedHost := u.Host

	onLog(fmt.Sprintf("[CRAWLER] Initiating crawl workflow for seed: %s", seedURL))

	// Instantiate shared crawl session
	endpointsChan := make(chan DiscoveredEndpoint, 500)
	errorsChan := make(chan string, 100)

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	session := &CrawlSession{
		ScanID:     scanID,
		SeedURL:    seedURL,
		SeedHost:   seedHost,
		Client:     cm.client,
		MaxDepth:   2,
		Endpoints:  endpointsChan,
		ErrorLogs:  errorsChan,
		CancelFunc: cancel,
	}

	// 1. Run robots.txt & Sitemap extraction concurrently
	var sitemapURLs []string
	onLog("[CRAWLER] Checking robots.txt and sitemaps...")
	disallows, sitemaps, err := ParseRobots(sessionCtx, cm.client, seedURL)
	if err != nil {
		onLog(fmt.Sprintf("[CRAWLER] robots.txt fetch skipped: %v", err))
	} else {
		onLog(fmt.Sprintf("[CRAWLER] robots.txt found %d disallow paths and %d sitemaps", len(disallows), len(sitemaps)))
		
		// Log disallow routes as potential endpoints
		for _, path := range disallows {
			resolved := resolveURL(u, path)
			if resolved != "" && IsInCrawlScope(resolved, seedURL) {
				endpointsChan <- DiscoveredEndpoint{
					Method: "GET",
					URL:    resolved,
					Source: "robots",
				}
			}
		}

		// Fetch and parse all discovered sitemaps
		for _, sm := range sitemaps {
			urls, err := ParseSitemap(sessionCtx, cm.client, sm)
			if err == nil {
				sitemapURLs = append(sitemapURLs, urls...)
				for _, smURL := range urls {
					if IsInCrawlScope(smURL, seedURL) {
						endpointsChan <- DiscoveredEndpoint{
							Method: "GET",
							URL:    smURL,
							Source: "sitemap",
						}
					}
				}
			}
		}
	}

	// Start a background listener to process discovered endpoints and print logs
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case ep, ok := <-endpointsChan:
				if !ok {
					return
				}
				onLog(fmt.Sprintf("[CRAWLER] Discovered route: %s %s (Source: %s)", ep.Method, ep.URL, ep.Source))
				if onEndpoint != nil {
					onEndpoint(ep.Method, ep.URL, ep.Source)
				}
			case errMsg, ok := <-errorsChan:
				if !ok {
					return
				}
				log.Printf("[Crawler Error] %s", errMsg)
			case <-sessionCtx.Done():
				return
			}
		}
	}()

	// 2. Try Katana crawler if available; otherwise try browser crawl if online; fallback to static BFS
	if attack.ToolAvailable("katana") {
		onLog("[CRAWLER] Katana crawler binary is available. Running Katana crawl...")
		err := attack.RunKatanaCrawl(sessionCtx, seedURL, cm.proxyPort, func(method, urlStr, source string) {
			endpointsChan <- DiscoveredEndpoint{
				Method: method,
				URL:    urlStr,
				Source: source,
			}
		})
		if err == nil {
			onLog("[CRAWLER] Katana crawler crawl completed successfully.")
			close(endpointsChan)
			close(errorsChan)
			wg.Wait()
			onLog(fmt.Sprintf("[CRAWLER] Crawl phase completed for Scan ID: %s", scanID))
			return nil
		}
		onLog(fmt.Sprintf("[CRAWLER] [ERROR] Katana crawl failed, falling back: %v", err))
	}

	browserClient := browser.NewClient("")
	if browserClient.IsOnline(sessionCtx) {
		onLog("[CRAWLER] Browser crawling service is online. Running Playwright dynamic crawler...")
		endpoints, forms, err := browserClient.Crawl(sessionCtx, scanID, seedURL, cm.proxyPort)
		if err != nil {
			onLog(fmt.Sprintf("[CRAWLER] [ERROR] Browser crawl failed, falling back to static crawl: %v", err))
			runStaticBFS(sessionCtx, session, endpointsChan, errorsChan, seedURL, sitemapURLs, seedHost, onLog, cm)
		} else {
			onLog(fmt.Sprintf("[CRAWLER] Browser crawl succeeded. Processing %d discovered routes and %d forms.", len(endpoints), len(forms)))
			for _, ep := range endpoints {
				endpointsChan <- DiscoveredEndpoint{
					Method: ep.Method,
					URL:    ep.URL,
					Source: ep.Source,
				}
			}
			for _, f := range forms {
				if onForm != nil {
					onForm(f)
				}
			}
		}
	} else {
		onLog("[CRAWLER] Browser crawling service is offline. Falling back to static BFS crawler...")
		runStaticBFS(sessionCtx, session, endpointsChan, errorsChan, seedURL, sitemapURLs, seedHost, onLog, cm)
	}

	// Clean up listeners
	close(endpointsChan)
	close(errorsChan)
	wg.Wait()

	onLog(fmt.Sprintf("[CRAWLER] Crawl phase completed for Scan ID: %s", scanID))
	return nil
}

func runStaticBFS(
	ctx context.Context,
	session *CrawlSession,
	endpointsChan chan DiscoveredEndpoint,
	errorsChan chan string,
	seedURL string,
	sitemapURLs []string,
	seedHost string,
	onLog func(msg string),
	cm *CrawlManager,
) {
	// Build our BFS Queue starting with the seed URL and sitemap URLs
	currentDepthURLs := []string{seedURL}
	for _, smURL := range sitemapURLs {
		if IsInCrawlScope(smURL, seedURL) {
			currentDepthURLs = append(currentDepthURLs, smURL)
			// Trigger HTTP page load to log through proxy
			endpointsChan <- DiscoveredEndpoint{
				Method: "GET",
				URL:    smURL,
				Source: "sitemap",
			}
		}
	}

	// BFS Crawl Loop
	concurrencyLimit := 5
	for depth := 1; depth <= session.MaxDepth; depth++ {
		if len(currentDepthURLs) == 0 {
			break
		}

		onLog(fmt.Sprintf("[CRAWLER] Crawling Depth %d (%d pages in queue)...", depth, len(currentDepthURLs)))

		var nextDepthURLs []string
		var nextDepthMutex sync.Mutex
		
		// Setup worker channel to limit concurrency
		sem := make(chan struct{}, concurrencyLimit)
		var crawlWg sync.WaitGroup

		for _, link := range currentDepthURLs {
			select {
			case <-ctx.Done():
				break
			default:
			}

			crawlWg.Add(1)
			sem <- struct{}{}

			go func(targetLink string) {
				defer func() {
					<-sem
					crawlWg.Done()
				}()

				// Fetch and parse current link
				foundLinks, jsFiles := CrawlPage(ctx, session, targetLink, depth)

				// Process extracted JS files for endpoint scanning
				var jsDiscoveredLinks []string
				for _, jsURL := range jsFiles {
					onLog(fmt.Sprintf("[CRAWLER] Analyzing script: %s", jsURL))
					urls, err := ExtractEndpointsFromJS(ctx, cm.client, jsURL)
					if err == nil && len(urls) > 0 {
						onLog(fmt.Sprintf("[CRAWLER] Script analysis mapped %d paths in %s", len(urls), jsURL))
						jsDiscoveredLinks = append(jsDiscoveredLinks, urls...)
					}
				}

				// Collect and merge links for the next depth tier
				nextDepthMutex.Lock()
				defer nextDepthMutex.Unlock()

				for _, link := range foundLinks {
					if IsInCrawlScope(link, seedURL) {
						nextDepthURLs = append(nextDepthURLs, link)
					}
				}
				for _, link := range jsDiscoveredLinks {
					if IsInCrawlScope(link, seedURL) {
						nextDepthURLs = append(nextDepthURLs, link)
						// Notify log of JS endpoint discovery
						endpointsChan <- DiscoveredEndpoint{
							Method: "GET",
							URL:    link,
							Source: "js_analyzer",
						}
					}
				}
			}(link)
		}

		crawlWg.Wait()
		currentDepthURLs = nextDepthURLs
		
		// Add small delay between depth tiers to respect rate limits
		time.Sleep(500 * time.Millisecond)
	}
}
