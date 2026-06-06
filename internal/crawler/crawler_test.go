package crawler

import (
	"context"
	"strings"
	"testing"

	"github.com/parth/lastresort/tests/fixtures"
)

func TestCrawlerDiscovery(t *testing.T) {
	server := fixtures.NewTargetApp()
	defer server.Close()

	ctx := context.Background()
	cm := NewCrawlManager("scan-crawl-test", 9999) // forces fallback to direct client

	var discovered []string
	onLog := func(msg string) {
		if strings.Contains(msg, "Discovered route:") {
			discovered = append(discovered, msg)
		}
	}

	var endpoints []string
	err := cm.Crawl(ctx, "scan-crawl-test", server.URL, "", onLog, func(method, urlStr, source string) {
		endpoints = append(endpoints, urlStr)
	}, nil)
	if err != nil {
		t.Fatalf("crawler Crawl failed: %v", err)
	}

	if len(endpoints) == 0 {
		t.Error("expected at least some endpoints collected, got 0")
	}

	// Verify that Sitemap and Robots disallow rules were hit
	foundRobotsDisallow := false
	foundSitemapLoc := false
	for _, route := range discovered {
		if strings.Contains(route, "/hidden-admin") {
			foundRobotsDisallow = true
		}
		if strings.Contains(route, "/search?q=test") {
			foundSitemapLoc = true
		}
	}

	if !foundRobotsDisallow {
		t.Error("crawler failed to discover robots.txt Disallow route (/hidden-admin)")
	}
	if !foundSitemapLoc {
		t.Error("crawler failed to discover sitemap location route (/search?q=test)")
	}
}
