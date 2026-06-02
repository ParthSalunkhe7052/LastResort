package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Regex patterns to identify relative routes/endpoints in JS source code.
var (
	// Matches quoted relative paths: "/api/v1/users", "/login", etc.
	relativeRouteRegex = regexp.MustCompile(`['"](\/[a-zA-Z0-9_\-\/]{2,100})['"]`)
	
	// Matches specific API routes like "/api/..."
	apiRouteRegex = regexp.MustCompile(`(\/api\/[a-zA-Z0-9_\-\/]+)`)
)

// ExtractEndpointsFromJS fetches a JavaScript file and parses it using regular expressions
// to discover potential endpoints or subpaths.
func ExtractEndpointsFromJS(ctx context.Context, client *http.Client, jsURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JS asset returned status: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JS body: %w", err)
	}
	jsContent := string(bodyBytes)

	// Keep track of unique discovered paths
	discoveredPaths := make(map[string]bool)

	// 1. Scan for relative routes in quotes
	matches := relativeRouteRegex.FindAllStringSubmatch(jsContent, -1)
	for _, m := range matches {
		if len(m) > 1 {
			path := strings.TrimSpace(m[1])
			if shouldKeepPath(path) {
				discoveredPaths[path] = true
			}
		}
	}

	// 2. Scan for raw API paths
	apiMatches := apiRouteRegex.FindAllString(jsContent, -1)
	for _, path := range apiMatches {
		path = strings.TrimSpace(path)
		if shouldKeepPath(path) {
			discoveredPaths[path] = true
		}
	}

	// Parse JS URL to resolve relative endpoints
	parsedJSURL, err := url.Parse(jsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JS URL: %w", err)
	}

	var absoluteURLs []string
	for path := range discoveredPaths {
		// Resolve the absolute URL relative to the JS host
		refURL, err := url.Parse(path)
		if err == nil {
			resolved := parsedJSURL.ResolveReference(refURL)
			absoluteURLs = append(absoluteURLs, resolved.String())
		}
	}

	return absoluteURLs, nil
}

// shouldKeepPath filters out paths that are unlikely to be endpoints (e.g. assets, static file extensions).
func shouldKeepPath(path string) bool {
	// Filter out common static assets and libraries
	lower := strings.ToLower(path)
	
	// Skip common file extensions that are not active endpoints
	ignoredExtensions := []string{
		".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", 
		".ttf", ".eot", ".mp4", ".mp3", ".webm", ".pdf", ".zip", ".tar.gz",
	}
	for _, ext := range ignoredExtensions {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}

	// Skip framework-specific artifacts or generic config entries
	ignoredPatterns := []string{
		"/node_modules/", "/react/", "/vue/", "/angular/", "http://", "https://",
	}
	for _, pat := range ignoredPatterns {
		if strings.Contains(lower, pat) {
			return false
		}
	}

	// Paths should be at least 2 chars long and start with a slash
	return len(path) >= 2 && strings.HasPrefix(path, "/")
}
