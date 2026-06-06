package scanner

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/parth/lastresort/internal/storage"
)

// ScanRateLimit [DEPRECATED] sends 10 consecutive requests with a 100ms delay to check for basic rate limiting via direct net/http.
// Use runAgentRateLimit in internal/orchestrator for modern, browser-aware rate limit testing.
func (as *ActiveScanner) ScanRateLimit(ctx context.Context, scanID, urlStr string) error {
	successCount := 0
	throttled := false

	for i := 0; i < 10; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}

		req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		if err != nil {
			continue
		}

		resp, err := as.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 429 || resp.StatusCode == 403 {
			throttled = true
			break
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			successCount++
		}
	}

	if successCount == 10 && !throttled {
		title := "Missing Rate Limiting Protection"
		description := fmt.Sprintf("The application responded to 10 consecutive rapid requests without returning a 429 Too Many Requests or any throttling/block signal. This suggests lack of rate limiting controls on: %s", urlStr)
		severity := "INFO"

		_, err := as.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            scanID,
			Title:             title,
			Description:       description,
			Severity:          severity,
			VulnerabilityType: "Rate Limit Testing",
			Endpoint:          urlStr,
			Payload:           "10 requests / 1s",
			ResponseStatus:    200,
			Confidence:        0.5,
		}, storage.EvidenceInput{
			FlowID:          0,
			EvidenceType:    storage.EvidenceTiming,
			RequestExcerpt:  fmt.Sprintf("GET %s (10 requests, 100ms delay)", urlStr),
			ResponseExcerpt: "no 429/403 observed in burst test",
		})
		if err != nil {
			log.Printf("[Rate Limit Scanner] [ERROR] Failed to save finding: %v", err)
		}
	}

	return nil
}
