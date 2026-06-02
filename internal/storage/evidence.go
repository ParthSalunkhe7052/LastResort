package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

type EvidenceType string

const (
	EvidenceHTTPFlow EvidenceType = "HTTP_FLOW"
	EvidenceHeader   EvidenceType = "HEADER_MATCH"
	EvidenceBody     EvidenceType = "BODY_MATCH"
	EvidenceTiming   EvidenceType = "TIMING"
)

type FindingEvidence struct {
	ID             string `json:"id"`
	FindingID      string `json:"finding_id"`
	FlowID         int64  `json:"flow_id"`
	EvidenceType   string `json:"evidence_type"`
	RequestExcerpt string `json:"request_excerpt"`
	ResponseExcerpt string `json:"response_excerpt"`
	ScreenshotPath string `json:"screenshot_path"`
	CreatedAt      string `json:"created_at"`
}

type EvidenceInput struct {
	FlowID          int64
	EvidenceType    EvidenceType
	RequestExcerpt  string
	ResponseExcerpt string
	ScreenshotPath  string
}

func (db *DB) AddFindingEvidence(ctx context.Context, findingID string, ev EvidenceInput) (string, error) {
	if findingID == "" {
		return "", fmt.Errorf("findingID is required")
	}
	if ev.FlowID <= 0 {
		return "", fmt.Errorf("flow_id is required for evidence")
	}
	if ev.EvidenceType == "" {
		return "", fmt.Errorf("evidence_type is required")
	}

	id := uuid.New().String()
	_, err := db.ExecContext(ctx,
		`INSERT INTO finding_evidence (id, finding_id, flow_id, evidence_type, request_excerpt, response_excerpt, screenshot_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, findingID, ev.FlowID, string(ev.EvidenceType), ev.RequestExcerpt, ev.ResponseExcerpt, ev.ScreenshotPath,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert finding evidence: %w", err)
	}
	return id, nil
}

