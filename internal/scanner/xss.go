package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/parth/lastresort/internal/storage"
)

// xssContext describes where in an HTML document a reflection lands.
type xssContext string

const (
	xssContextHTML      xssContext = "html_body"
	xssContextAttribute xssContext = "html_attribute"
	xssContextScript    xssContext = "script_block"
	xssContextUnknown   xssContext = "unknown"
)

// xssPayload pairs an executable payload with its detection marker.
type xssPayload struct {
	payload string
	marker  string // unique string that proves execution or reflection
}

// ScanXSS runs context-aware reflected XSS checks.
// Detection stages:
//  1. Send a canary probe to find reflected parameters.
//  2. Detect the reflection context (HTML body / attribute / script block).
//  3. Send a context-appropriate executable payload.
//  4. Check if the executable payload is reflected un-encoded (proves execution risk).
func (as *ActiveScanner) ScanXSS(ctx context.Context, scanID, method, urlStr string, body []byte, contentType string) error {
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

		// Stage 1: Canary probe — unique marker that won't collide with page content.
		canary := fmt.Sprintf("lr%sxss", pt.Name[:min(4, len(pt.Name))])
		xssCtx := as.detectReflectionContext(ctx, method, urlStr, body, contentType, pt, canary)
		if xssCtx == "" {
			// Not reflected at all — skip this parameter.
			continue
		}

		// Stage 2: Choose payload based on reflection context.
		exec := contextPayload(xssCtx)

		// Stage 3: Send executable payload.
		injectedURL, injectedBody := BuildInjectedRequest(method, urlStr, body, contentType, pt, exec.payload)
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

		respContent := string(respBytes)

		// Stage 4: Check if the marker appears un-encoded.
		if !strings.Contains(respContent, exec.marker) {
			continue
		}

		// Check for CSP that may mitigate — note it, lower confidence.
		csp := resp.Header.Get("Content-Security-Policy")
		confidence := 0.95
		description := fmt.Sprintf(
			"Reflected XSS in parameter %q (context: %s). Payload %q was reflected un-encoded. "+
				"The application does not encode user-supplied input before placing it into the HTML response.",
			pt.Name, xssCtx, exec.payload)
		if csp != "" {
			confidence = 0.60
			description += fmt.Sprintf(" Note: Content-Security-Policy header is present (%q), which may partially mitigate exploitability. Manual verification recommended.", csp)
		}

		// Save the HTTP flow as evidence.
		flowID, flowErr := as.db.SaveFlow(ctx, scanID, method, injectedURL, req.Header, injectedBody, resp.Header, respBytes, resp.StatusCode)
		if flowErr != nil {
			continue
		}

		respExcerpt := respContent
		if len(respExcerpt) > 2000 {
			respExcerpt = respExcerpt[:2000]
		}

		_, err = as.db.SaveFindingWithEvidence(ctx, storage.FindingInput{
			ScanID:            scanID,
			Title:             fmt.Sprintf("Reflected XSS in Parameter: %s (context: %s)", pt.Name, xssCtx),
			Description:       description,
			Severity:          "HIGH",
			VulnerabilityType: "Reflected XSS",
			Endpoint:          injectedURL,
			Payload:           exec.payload,
			ResponseStatus:    resp.StatusCode,
			Confidence:        confidence,
			Category:          "VERIFIED_ATTACK",
		}, storage.EvidenceInput{
			FlowID:          flowID,
			EvidenceType:    storage.EvidenceBody,
			RequestExcerpt:  fmt.Sprintf("%s %s (param: %s, context: %s)", method, injectedURL, pt.Name, xssCtx),
			ResponseExcerpt: respExcerpt,
		})
		if err != nil {
			log.Printf("[XSS Scanner] [ERROR] Failed to save finding: %v", err)
		}
	}

	return nil
}

// detectReflectionContext sends a canary and determines where in the document it appears.
// Returns empty string if the canary is not reflected.
func (as *ActiveScanner) detectReflectionContext(ctx context.Context, method, urlStr string, body []byte, contentType string, pt InsertionPoint, canary string) xssContext {
	injectedURL, injectedBody := BuildInjectedRequest(method, urlStr, body, contentType, pt, canary)
	req, err := http.NewRequestWithContext(ctx, method, injectedURL, bytes.NewReader(injectedBody))
	if err != nil {
		return ""
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := as.client.Do(req)
	if err != nil {
		return ""
	}
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	resp.Body.Close()

	html := string(respBytes)
	idx := strings.Index(html, canary)
	if idx < 0 {
		return "" // not reflected
	}

	// Check surrounding characters to classify context.
	contextWindow := ""
	start := max(0, idx-100)
	end := min(len(html), idx+len(canary)+100)
	contextWindow = html[start:end]

	lctx := strings.ToLower(contextWindow)

	// Inside a <script> block?
	if strings.Contains(lctx[:min(100, len(lctx))], "<script") || strings.Contains(lctx, "function(") || strings.Contains(lctx, "var ") {
		return xssContextScript
	}
	// Inside an HTML attribute? Check for attribute syntax before the canary.
	prefix := html[start:idx]
	if strings.Count(prefix, "\"")%2 == 1 || strings.Count(prefix, "'")%2 == 1 {
		return xssContextAttribute
	}
	// Default: HTML body context
	return xssContextHTML
}

// contextPayload selects the most effective payload for the detected reflection context.
func contextPayload(ctx xssContext) xssPayload {
	switch ctx {
	case xssContextScript:
		// Already inside a script block — break out of string context.
		return xssPayload{
			payload: `";alert(1);//`,
			marker:  `alert(1)`,
		}
	case xssContextAttribute:
		// Inside an attribute value — escape the attribute and open a new event handler.
		return xssPayload{
			payload: `" onmouseover="alert(1)`,
			marker:  `onmouseover="alert(1)`,
		}
	default:
		// HTML body — inject a script tag.
		return xssPayload{
			payload: `<script>alert(1)</script>`,
			marker:  `<script>alert(1)</script>`,
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
