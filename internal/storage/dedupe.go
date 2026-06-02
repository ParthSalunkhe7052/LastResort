package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// GenerateFingerprint computes a deterministic SHA-256 hash for deduplication based on vulnerability type, endpoint, and normalized title.
func GenerateFingerprint(vulnType, endpoint, title string) string {
	normVuln := strings.TrimSpace(strings.ToLower(vulnType))
	normEndpoint := strings.TrimSpace(strings.ToLower(endpoint))
	normTitle := strings.TrimSpace(strings.ToLower(title))

	// Join with a separator to avoid boundary collisions
	input := normVuln + "|" + normEndpoint + "|" + normTitle
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}
