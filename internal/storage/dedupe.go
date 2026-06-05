package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
)

// GenerateFingerprint computes a deterministic SHA-256 hash for deduplication based on vulnerability type, endpoint, and normalized title.
// For passive/site-wide vulnerabilities (e.g., missing headers, CORS issues), we group them at the host level rather than path level.
func GenerateFingerprint(vulnType, endpoint, title string) string {
	normVuln := strings.TrimSpace(strings.ToLower(vulnType))
	normEndpoint := strings.TrimSpace(strings.ToLower(endpoint))
	normTitle := strings.TrimSpace(strings.ToLower(title))

	// Group passive/config findings at host level to avoid path-level duplication
	isPassiveOrConfig := normVuln == "security misconfiguration" ||
		strings.Contains(normVuln, "missing header") ||
		strings.Contains(normVuln, "cors") ||
		strings.Contains(normTitle, "content-security-policy") ||
		strings.Contains(normTitle, "strict-transport-security") ||
		strings.Contains(normTitle, "x-frame-options") ||
		strings.Contains(normTitle, "x-content-type-options") ||
		strings.Contains(normTitle, "cookie")

	if isPassiveOrConfig {
		if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
			normEndpoint = u.Scheme + "://" + u.Host
		}
	}

	// Join with a separator to avoid boundary collisions
	input := normVuln + "|" + normEndpoint + "|" + normTitle
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

