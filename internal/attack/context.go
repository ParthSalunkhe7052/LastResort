package attack

// BrowserContext represents the complete state of a browser session
// that the AI needs before making attack decisions.
type BrowserContext struct {
	SessionID       string            `json:"session_id"`
	CurrentURL      string            `json:"current_url"`
	PageTitle       string            `json:"page_title"`
	PageSource      string            `json:"page_source"`
	Screenshot      string            `json:"screenshot"` // base64
	Cookies         map[string]string `json:"cookies"`
	LocalStorage    map[string]string `json:"local_storage"`
	Forms           []BrowserForm     `json:"forms"`
	Inputs          []BrowserElement  `json:"inputs"`
	Buttons         []BrowserElement  `json:"buttons"`
	Links           []BrowserElement  `json:"links"`
	AuthState       string            `json:"auth_state"` // anonymous, user, admin
	PreviousActions []ActionResult    `json:"previous_actions"`
}

// BrowserElement represents a DOM element with its selector.
type BrowserElement struct {
	Tag      string `json:"tag"`
	Text     string `json:"text"`
	Selector string `json:"selector"`
	Href     string `json:"href,omitempty"`
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Value    string `json:"value,omitempty"`
	Type     string `json:"type,omitempty"`
}

// BrowserForm represents an HTML form.
type BrowserForm struct {
	Selector string           `json:"selector"`
	Action   string           `json:"action"`
	Method   string           `json:"method"`
	Inputs   []BrowserElement `json:"inputs"`
	Submit   *BrowserElement  `json:"submit,omitempty"`
}
