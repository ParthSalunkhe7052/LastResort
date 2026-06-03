package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/parth/lastresort/internal/storage"
)

// sqliState tracks the detection confidence state for a finding.
type sqliState string

const (
	sqliSuspected sqliState = "SUSPECTED"
	sqliVerified  sqliState = "VERIFIED"
)

// sqliResult holds all evidence collected for a single parameter.
type sqliResult struct {
	state      sqliState
	payload    string
	param      string
	evidence   string
	baseStatus int
	vulnStatus int
}

// ScanSQLi [DEPRECATED] runs legacy multi-stage SQL injection checks via net/http.
// Use runAgentSqli in internal/orchestrator for modern, browser-aware SQLi testing.
func (as *ActiveScanner) ScanSQLi(ctx context.Context, scanID, method, urlStr string, body []byte, contentType string) error {
	points, err := ExtractInsertionPoints(method, urlStr, body, contentType)
	if err != nil {
		return err
	}

	for _, pt := range points {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		result := as.runSQLiChecks(ctx, method, urlStr, body, contentType, pt)
		if result == nil {
			continue
		}

		// Save flow for this injection
		injectedURL, injectedBody := BuildInjectedRequest(method, urlStr, body, contentType, pt, result.payload)
		req, err := http.NewRequestWithContext(ctx, method, injectedURL, bytes.NewReader(injectedBody))
		if err != nil {
			continue
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := as.client.Do(req)
		if err != nil {
			continue
		}
		respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
		resp.Body.Close()

		flowID, flowErr := as.db.SaveFlow(ctx, scanID, method, injectedURL, req.Header, injectedBody, resp.Header, respBytes, resp.StatusCode)
		if flowErr != nil {
			continue
		}

		title := fmt.Sprintf("SQL Injection in Parameter: %s [%s]", result.param, result.state)
		description := result.evidence
		severity := "HIGH"
		confidence := 0.75
		category := "ATTEMPT"
		if result.state == sqliVerified {
			confidence = 0.95
			category = "VERIFIED_ATTACK"
			severity = "CRITICAL"
		}

		respExcerpt := string(respBytes)
		if len(respExcerpt) > 2000 {
			respExcerpt = respExcerpt[:2000]
		}
		_, err = as.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            scanID,
			Title:             title,
			Description:       description,
			Severity:          severity,
			VulnerabilityType: "SQL Injection",
			Endpoint:          injectedURL,
			Payload:           result.payload,
			ResponseStatus:    resp.StatusCode,
			Confidence:        confidence,
			Category:          category,
		}, storage.EvidenceInput{
			FlowID:          flowID,
			EvidenceType:    storage.EvidenceBody,
			RequestExcerpt:  fmt.Sprintf("%s %s (param: %s payload: %q)", method, injectedURL, result.param, result.payload),
			ResponseExcerpt: respExcerpt,
		})
		if err != nil {
			log.Printf("[SQLi Scanner] [ERROR] Failed to save finding: %v", err)
		}
	}

	return nil
}

// runSQLiChecks tries all detection strategies and returns the first result found.
func (as *ActiveScanner) runSQLiChecks(ctx context.Context, method, urlStr string, body []byte, contentType string, pt InsertionPoint) *sqliResult {
	// Stage 1: Get a clean baseline response for the parameter's current value.
	baseResp, baseBody, baseStatus, baseTime := as.fetchBaseline(ctx, method, urlStr, body, contentType, pt)
	if baseResp == nil {
		return nil
	}

	// Stage 2: Error-based detection
	if result := as.checkErrorBased(ctx, method, urlStr, body, contentType, pt, baseStatus); result != nil {
		return result
	}

	// Stage 3: Boolean-based detection (requires a stable baseline)
	if result := as.checkBooleanBased(ctx, method, urlStr, body, contentType, pt, baseBody, baseStatus); result != nil {
		return result
	}

	// Stage 4: Time-based (blind) detection
	if result := as.checkTimeBased(ctx, method, urlStr, body, contentType, pt, baseTime); result != nil {
		return result
	}

	return nil
}

// checkErrorBased tests for database error messages in the response.
func (as *ActiveScanner) checkErrorBased(ctx context.Context, method, urlStr string, body []byte, contentType string, pt InsertionPoint, baseStatus int) *sqliResult {
	errorPayloads := []string{"'", "\"", "')", "1 OR 1=1", "1' OR '1'='1"}
	errorMarkers := []string{
		"sql syntax", "sqlite", "postgresql", "mysql", "ora-", "odbc",
		"syntax error", "db error", "unclosed quotation", "unterminated string",
		"quoted string not properly terminated",
	}

	for _, payload := range errorPayloads {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		injectedURL, injectedBody := BuildInjectedRequest(method, urlStr, body, contentType, pt, payload)
		req, err := http.NewRequestWithContext(ctx, method, injectedURL, bytes.NewReader(injectedBody))
		if err != nil {
			continue
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := as.client.Do(req)
		if err != nil {
			continue
		}
		respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
		resp.Body.Close()

		respLower := strings.ToLower(string(respBytes))
		for _, marker := range errorMarkers {
			if strings.Contains(respLower, marker) {
				return &sqliResult{
					state:      sqliVerified,
					payload:    payload,
					param:      pt.Name,
					evidence:   fmt.Sprintf("Database error detected in response to payload %q in parameter %q. Error marker: %q. Stage: error-based.", payload, pt.Name, marker),
					baseStatus: baseStatus,
					vulnStatus: resp.StatusCode,
				}
			}
		}
	}
	return nil
}

// checkBooleanBased compares two responses: a true-condition vs a false-condition.
// A significant difference in response length or status indicates injectable parameter.
func (as *ActiveScanner) checkBooleanBased(ctx context.Context, method, urlStr string, body []byte, contentType string, pt InsertionPoint, baseBody []byte, baseStatus int) *sqliResult {
	truePayload := "1 AND 1=1"
	falsePayload := "1 AND 1=2"

	trueURL, trueBodyB := BuildInjectedRequest(method, urlStr, body, contentType, pt, truePayload)
	falseURL, falseBodyB := BuildInjectedRequest(method, urlStr, body, contentType, pt, falsePayload)

	trueReq, err := http.NewRequestWithContext(ctx, method, trueURL, bytes.NewReader(trueBodyB))
	if err != nil {
		return nil
	}
	if contentType != "" {
		trueReq.Header.Set("Content-Type", contentType)
	}
	trueResp, err := as.client.Do(trueReq)
	if err != nil {
		return nil
	}
	trueBytes, _ := io.ReadAll(io.LimitReader(trueResp.Body, 100*1024))
	trueResp.Body.Close()

	falseReq, err := http.NewRequestWithContext(ctx, method, falseURL, bytes.NewReader(falseBodyB))
	if err != nil {
		return nil
	}
	if contentType != "" {
		falseReq.Header.Set("Content-Type", contentType)
	}
	falseResp, err := as.client.Do(falseReq)
	if err != nil {
		return nil
	}
	falseBytes, _ := io.ReadAll(io.LimitReader(falseResp.Body, 100*1024))
	falseResp.Body.Close()

	// Calculate deltas
	baseLen := len(baseBody)
	trueLen := len(trueBytes)
	falseLen := len(falseBytes)

	// True condition should match baseline; false should be significantly different.
	trueDelta := abs(trueLen - baseLen)
	falseDelta := abs(falseLen - baseLen)
	trueFalseDelta := abs(trueLen - falseLen)

	// Require: true~=base, false significantly different, and a meaningful absolute delta.
	if trueDelta < 50 && falseDelta > 200 && trueFalseDelta > 200 {
		return &sqliResult{
			state:      sqliSuspected,
			payload:    falsePayload,
			param:      pt.Name,
			evidence:   fmt.Sprintf("Boolean-based SQLi suspected in parameter %q. TRUE condition response length: %d (delta from baseline: %d). FALSE condition response length: %d (delta from baseline: %d). A %d byte differential indicates conditional branching in the backend query.", pt.Name, trueLen, trueDelta, falseLen, falseDelta, trueFalseDelta),
			baseStatus: baseStatus,
			vulnStatus: falseResp.StatusCode,
		}
	}

	return nil
}

// checkTimeBased sends a payload that causes deliberate DB sleep and measures response latency.
func (as *ActiveScanner) checkTimeBased(ctx context.Context, method, urlStr string, body []byte, contentType string, pt InsertionPoint, baseTime time.Duration) *sqliResult {
	// 3-second sleep payloads for multiple DBMS
	sleepPayloads := []string{
		"1; WAITFOR DELAY '0:0:3'--",      // MSSQL
		"1 AND SLEEP(3)--",                // MySQL
		"1; SELECT pg_sleep(3)--",         // PostgreSQL
		"1 AND 3=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--", // SQLite heavy
	}

	sleepThreshold := 2500 * time.Millisecond

	for _, payload := range sleepPayloads {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		injectedURL, injectedBody := BuildInjectedRequest(method, urlStr, body, contentType, pt, payload)
		req, err := http.NewRequestWithContext(ctx, method, injectedURL, bytes.NewReader(injectedBody))
		if err != nil {
			continue
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		start := time.Now()
		resp, err := as.client.Do(req)
		elapsed := time.Since(start)

		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		// Only flag if significantly above baseline latency AND above our absolute threshold
		if elapsed > sleepThreshold && elapsed > baseTime+1500*time.Millisecond {
			return &sqliResult{
				state:   sqliVerified,
				payload: payload,
				param:   pt.Name,
				evidence: fmt.Sprintf("Time-based blind SQLi detected in parameter %q. Payload %q caused a response delay of %s (baseline: %s, threshold: %s). This indicates the database executed a sleep/delay function.",
					pt.Name, payload, elapsed.Round(time.Millisecond), baseTime.Round(time.Millisecond), sleepThreshold),
				baseStatus: 200,
				vulnStatus: resp.StatusCode,
			}
		}
	}
	return nil
}

// fetchBaseline sends the original request as-is and returns the response body, status, and latency.
func (as *ActiveScanner) fetchBaseline(ctx context.Context, method, urlStr string, body []byte, contentType string, pt InsertionPoint) (resp *http.Response, respBody []byte, status int, latency time.Duration) {
	// Inject the original value (unchanged) to get a clean baseline
	baseURL, baseBody := BuildInjectedRequest(method, urlStr, body, contentType, pt, pt.Value)
	req, err := http.NewRequestWithContext(ctx, method, baseURL, bytes.NewReader(baseBody))
	if err != nil {
		return nil, nil, 0, 0
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	start := time.Now()
	resp, err = as.client.Do(req)
	latency = time.Since(start)
	if err != nil {
		return nil, nil, 0, 0
	}
	respBody, _ = io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	resp.Body.Close()
	return resp, respBody, resp.StatusCode, latency
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
