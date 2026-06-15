package orchestrator

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/parth/lastresort/internal/attack"
)

// FindingAggregator handles deduplication, ranking, and selection of top findings.
type FindingAggregator struct {
	findings []attack.NormalizedFinding
}

// NewFindingAggregator creates a new aggregator.
func NewFindingAggregator() *FindingAggregator {
	return &FindingAggregator{}
}

// Add appends findings to the aggregator.
func (fa *FindingAggregator) Add(findings []attack.NormalizedFinding) {
	fa.findings = append(fa.findings, findings...)
}

// Deduplicate removes duplicate findings based on URL + category + parameter.
// When duplicates exist, the one with higher severity is kept.
func (fa *FindingAggregator) Deduplicate() []attack.NormalizedFinding {
	type key struct {
		URL      string
		Category string
		Parameter string
	}

	seen := make(map[key]attack.NormalizedFinding)
	for _, f := range fa.findings {
		k := key{
			URL:       normalizeURL(f.URL),
			Category:  strings.ToLower(f.Category),
			Parameter: strings.ToLower(f.Parameter),
		}
		existing, exists := seen[k]
		// Keep the one with higher severity, or if equal, prefer the verified one
		if !exists || severityWeight(f.Severity) > severityWeight(existing.Severity) || 
		   (severityWeight(f.Severity) == severityWeight(existing.Severity) && f.State == "VERIFIED_ATTACK" && existing.State != "VERIFIED_ATTACK") {
			seen[k] = f
		}
	}

	deduped := make([]attack.NormalizedFinding, 0, len(seen))
	for _, f := range seen {
		deduped = append(deduped, f)
	}
	fa.findings = deduped
	return deduped
}

// RankBySeverity sorts findings by severity (highest first), then by exploitability.
func (fa *FindingAggregator) RankBySeverity() []attack.NormalizedFinding {
	sort.Slice(fa.findings, func(i, j int) bool {
		wi := severityWeight(fa.findings[i].Severity)
		wj := severityWeight(fa.findings[j].Severity)
		if wi != wj {
			return wi > wj
		}
		ei := exploitabilityBonus(fa.findings[i])
		ej := exploitabilityBonus(fa.findings[j])
		return ei > ej
	})
	return fa.findings
}

// TopN returns the top N findings after deduplication and ranking.
func (fa *FindingAggregator) TopN(n int) []attack.NormalizedFinding {
	fa.Deduplicate()
	fa.RankBySeverity()
	if len(fa.findings) > n {
		return fa.findings[:n]
	}
	return fa.findings
}

// Summary returns a count-by-severity breakdown.
func (fa *FindingAggregator) Summary() map[string]int {
	summary := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
		"INFO":     0,
	}
	for _, f := range fa.findings {
		s := strings.ToUpper(f.Severity)
		if _, ok := summary[s]; ok {
			summary[s]++
		} else {
			summary["INFO"]++
		}
	}
	return summary
}

// ToAIContext formats the findings into a context string for the AI prompt.
func (fa *FindingAggregator) ToAIContext() string {
	var sb strings.Builder
	for i, f := range fa.findings {
		sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, f.Severity, f.Title))
		sb.WriteString(fmt.Sprintf("   Tool: %s | Category: %s | State: %s\n", f.Tool, f.Category, f.State))
		sb.WriteString(fmt.Sprintf("   URL: %s\n", f.URL))
		if f.Parameter != "" {
			sb.WriteString(fmt.Sprintf("   Parameter: %s\n", f.Parameter))
		}
		if f.Payload != "" {
			sb.WriteString(fmt.Sprintf("   Payload: %s\n", f.Payload))
		}
		if f.Evidence != "" {
			sb.WriteString(fmt.Sprintf("   Evidence: %s\n", f.Evidence))
		}
		if f.Description != "" {
			sb.WriteString(fmt.Sprintf("   Description: %s\n", f.Description))
		}
		if f.Remediation != "" {
			sb.WriteString(fmt.Sprintf("   Remediation: %s\n", f.Remediation))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// Findings returns all aggregated findings.
func (fa *FindingAggregator) Findings() []attack.NormalizedFinding {
	return fa.findings
}

func severityWeight(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 10
	case "HIGH":
		return 7
	case "MEDIUM":
		return 4
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

func exploitabilityBonus(f attack.NormalizedFinding) int {
	bonus := 0
	if f.State == "VERIFIED_ATTACK" {
		bonus += 5
	}
	if f.Payload != "" {
		bonus += 3
	}
	if strings.Contains(strings.ToLower(f.Category), "injection") ||
		strings.Contains(strings.ToLower(f.Category), "xss") ||
		strings.Contains(strings.ToLower(f.Category), "rce") {
		bonus += 2
	}
	if f.CurlCommand != "" {
		bonus += 1
	}
	return bonus
}

func normalizeURL(u string) string {
	u = strings.TrimSuffix(u, "/")
	u = strings.TrimSuffix(u, "/index.html")
	u = strings.TrimSuffix(u, "/index.php")
	return strings.ToLower(u)
}

// GenerateFingerprint creates a dedup fingerprint for a finding.
func GenerateFingerprint(vulnType, endpoint, title string) string {
	h := sha256.Sum256([]byte(strings.ToLower(vulnType + "|" + endpoint + "|" + title)))
	return fmt.Sprintf("%x", h[:8])
}
