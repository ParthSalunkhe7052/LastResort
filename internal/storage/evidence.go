package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

type EvidenceType string

const (
	// Passive / structural evidence
	EvidenceHTTPFlow  EvidenceType = "HTTP_FLOW"
	EvidenceHeader    EvidenceType = "HEADER_MATCH"
	EvidenceBody      EvidenceType = "BODY_MATCH"
	EvidenceTiming    EvidenceType = "TIMING"

	// Browser-driven evidence
	EvidenceScreenshot   EvidenceType = "SCREENSHOT"    // base64 Playwright screenshot
	EvidenceDOM          EvidenceType = "DOM_SNAPSHOT"  // page source after attack
	EvidenceBrowserEvent EvidenceType = "BROWSER_EVENT" // dialog / alert / mutation
	EvidenceRequest      EvidenceType = "REQUEST"       // outbound request detail
	EvidenceResponse     EvidenceType = "RESPONSE"      // raw response detail
)

// FindingEvidence is the full evidence record stored in the DB.
type FindingEvidence struct {
	ID              string `json:"id"`
	FindingID       string `json:"finding_id"`
	FlowID          int64  `json:"flow_id"`  // 0 for browser-driven attacks
	EvidenceType    string `json:"evidence_type"`
	RequestExcerpt  string `json:"request_excerpt"`
	ResponseExcerpt string `json:"response_excerpt"`
	ScreenshotPath  string `json:"screenshot_path"`
	CreatedAt       string `json:"created_at"`
}

// EvidenceInput is the caller-provided evidence bundle.
type EvidenceInput struct {
	FlowID          int64        // 0 is acceptable for browser-driven attacks
	EvidenceType    EvidenceType
	RequestExcerpt  string
	ResponseExcerpt string
	ScreenshotPath  string       // path on disk, or base64 stored inline
	ScreenshotB64   string       // base64 screenshot (stored as screenshot_path when no disk path)
}

// AddFindingEvidence persists evidence for an existing finding.
// FlowID of 0 is now allowed for browser-driven attack evidence.
func (db *DB) AddFindingEvidence(ctx context.Context, findingID string, ev EvidenceInput) (string, error) {
	if findingID == "" {
		return "", fmt.Errorf("findingID is required")
	}
	if ev.EvidenceType == "" {
		return "", fmt.Errorf("evidence_type is required")
	}

	// For browser-driven attacks the screenshot may be embedded as base64
	screenshotVal := ev.ScreenshotPath
	if screenshotVal == "" && ev.ScreenshotB64 != "" {
		screenshotVal = "data:image/png;base64," + ev.ScreenshotB64
	}

	// Enforce a minimum: we need either a request excerpt or response excerpt or screenshot
	if ev.RequestExcerpt == "" && ev.ResponseExcerpt == "" && screenshotVal == "" {
		return "", fmt.Errorf("evidence must have at least one of: request_excerpt, response_excerpt, screenshot")
	}

	flowID := ev.FlowID // 0 is stored as NULL via conditional below

	id := uuid.New().String()

	var err error
	if flowID > 0 {
		_, err = db.ExecContext(ctx,
			`INSERT INTO finding_evidence (id, finding_id, flow_id, evidence_type, request_excerpt, response_excerpt, screenshot_path)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, findingID, flowID, string(ev.EvidenceType), ev.RequestExcerpt, ev.ResponseExcerpt, screenshotVal,
		)
	} else {
		// Browser-driven: store NULL for flow_id (schema allows NULL after migration)
		_, err = db.ExecContext(ctx,
			`INSERT INTO finding_evidence (id, finding_id, flow_id, evidence_type, request_excerpt, response_excerpt, screenshot_path)
			 VALUES (?, ?, NULL, ?, ?, ?, ?)`,
			id, findingID, string(ev.EvidenceType), ev.RequestExcerpt, ev.ResponseExcerpt, screenshotVal,
		)
	}
	if err != nil {
		return "", fmt.Errorf("failed to insert finding evidence: %w", err)
	}
	return id, nil
}
