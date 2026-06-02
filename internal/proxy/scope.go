package proxy

import (
	"net"
	"net/url"
	"strings"
)

// IsInScope checks if the requested host is in scope for the active target URL.
func IsInScope(host string, targetURL string) bool {
	if targetURL == "" {
		return false
	}

	targetParsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	targetHost := targetParsed.Hostname()
	
	// Strip port from request host if present
	reqHost := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		reqHost = h
	}

	targetHost = strings.ToLower(strings.TrimSpace(targetHost))
	reqHost = strings.ToLower(strings.TrimSpace(reqHost))

	if targetHost == "" || reqHost == "" {
		return false
	}

	// Exact match
	if reqHost == targetHost {
		return true
	}

	// Subdomain match (e.g. api.example.com is in scope for target example.com)
	if strings.HasSuffix(reqHost, "."+targetHost) {
		return true
	}

	return false
}
