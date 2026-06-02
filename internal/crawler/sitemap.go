package crawler

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// SitemapURL represents a <url> entry in sitemap.xml
type SitemapURL struct {
	Loc string `xml:"loc"`
}

// SitemapIndexURL represents a <sitemap> entry in sitemap_index.xml
type SitemapIndexURL struct {
	Loc string `xml:"loc"`
}

// Sitemap represents a standard <urlset> sitemap
type Sitemap struct {
	XMLName xml.Name     `xml:"urlset"`
	URLs    []SitemapURL `xml:"url"`
}

// SitemapIndex represents a <sitemapindex> sitemap index file
type SitemapIndex struct {
	XMLName  xml.Name          `xml:"sitemapindex"`
	Sitemaps []SitemapIndexURL `xml:"sitemap"`
}

// ParseRobots fetches and parses the robots.txt file of a target URL.
// It returns a list of disallowed paths and a list of discovered sitemap URLs.
func ParseRobots(ctx context.Context, client *http.Client, targetURL string) ([]string, []string, error) {
	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// robots.txt is always at the root
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", parsedTarget.Scheme, parsedTarget.Host)

	req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch robots.txt: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("robots.txt returned status: %d", resp.StatusCode)
	}

	var disallows []string
	var sitemaps []string

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])

		if key == "disallow" {
			if val != "" {
				disallows = append(disallows, val)
			}
		} else if key == "sitemap" {
			if val != "" {
				sitemaps = append(sitemaps, val)
			}
		}
	}

	return disallows, sitemaps, nil
}

// ParseSitemap fetches and parses sitemap.xml or sitemap_index.xml.
// It returns a list of URLs discovered within the sitemap.
func ParseSitemap(ctx context.Context, client *http.Client, sitemapURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", sitemapURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch sitemap: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sitemap returned status: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read sitemap body: %w", err)
	}

	// Try to decode as a standard sitemap URL set
	var sitemap Sitemap
	if err := xml.Unmarshal(bodyBytes, &sitemap); err == nil && len(sitemap.URLs) > 0 {
		var urls []string
		for _, u := range sitemap.URLs {
			urls = append(urls, strings.TrimSpace(u.Loc))
		}
		return urls, nil
	}

	// Try to decode as a sitemap index (which points to other sitemaps)
	var index SitemapIndex
	if err := xml.Unmarshal(bodyBytes, &index); err == nil && len(index.Sitemaps) > 0 {
		var urls []string
		for _, sm := range index.Sitemaps {
			subUrls, err := ParseSitemap(ctx, client, strings.TrimSpace(sm.Loc))
			if err == nil {
				urls = append(urls, subUrls...)
			}
		}
		return urls, nil
	}

	return nil, fmt.Errorf("xml content did not match sitemap or sitemap index schemas")
}
