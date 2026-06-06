package attack

// ActionResult is the feedback from every browser action.
// The AI must receive this before deciding the next action.
type ActionResult struct {
	Success         bool            `json:"success"`
	FailureReason   string          `json:"failure_reason,omitempty"`
	CurrentURL      string          `json:"current_url"`
	PageTitle       string          `json:"page_title"`
	Screenshot      string          `json:"screenshot,omitempty"` // base64
	VisibleElements *BrowserContext `json:"visible_elements,omitempty"`
	NetworkEvents   []NetworkEvent  `json:"network_events,omitempty"`
	DurationMs      int64           `json:"duration_ms"`
	StatusCode      int             `json:"status_code,omitempty"`    // HTTP status if navigation occurred
	ResponseBody    string          `json:"response_body,omitempty"` // truncated
	Evidence        *AttackEvidence `json:"evidence,omitempty"`
}

// NetworkEvent captures a request made during the action.
type NetworkEvent struct {
	Method       string `json:"method"`
	URL          string `json:"url"`
	StatusCode   int    `json:"status_code"`
	ResourceType string `json:"resource_type"`
}

// AttackEvidence captures proof for a finding.
type AttackEvidence struct {
	RequestExcerpt  string `json:"request_excerpt"`
	ResponseExcerpt string `json:"response_excerpt"`
	ScreenshotPath  string `json:"screenshot_path,omitempty"`
	FlowID          int64  `json:"flow_id,omitempty"`
}
