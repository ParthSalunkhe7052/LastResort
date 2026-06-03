// Package attack provides the interface layer for goal-driven adversarial testing.
// Phase 6 implements the architecture: AttackPlanner, AttackExecutor, AttackVerifier.
// Concrete implementations are added in subsequent phases (Sessions, SQLMap, Nuclei).
package attack

import (
	"context"
	"net/http"
	"time"
)

// --- Core Types ---

// Session represents an isolated HTTP session (cookie jar + auth headers).
type Session struct {
	ID       string
	Role     string // anonymous, user, admin
	Username string
	Client   *http.Client // pre-configured with cookie jar and headers
	Headers  map[string]string
}

// AttackRequest is a concrete HTTP request prepared for attack execution.
type AttackRequest struct {
	Method      string
	URL         string
	Body        []byte
	ContentType string
	Headers     map[string]string
	Session     *Session
	// Metadata about what this request is testing
	GoalID      string
	Description string
}

// AttackResult captures the outcome of a single attack execution.
type AttackResult struct {
	Request      *AttackRequest
	Response     *AttackResponse
	Verdict      AttackVerdict
	Evidence     string
	ExtractedData string    // data that was accessed (proves unauthorized access)
	ExecutedAt   time.Time
	DurationMs   int64
}

// AttackResponse is the captured HTTP response from an attack.
type AttackResponse struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
	DurationMs int64
}

// AttackVerdict is the outcome classification of an attack attempt.
type AttackVerdict string

const (
	VerdictConfirmed   AttackVerdict = "CONFIRMED"    // attack achieved its goal with proof
	VerdictLikely      AttackVerdict = "LIKELY"        // strong indicators but not definitive proof
	VerdictFalsePositive AttackVerdict = "FALSE_POSITIVE" // attack appeared to succeed but verification failed
	VerdictInconclusive AttackVerdict = "INCONCLUSIVE"  // not enough signal to determine
	VerdictFailed      AttackVerdict = "FAILED"         // attack did not achieve its goal
)

// --- Interface Definitions ---

// AttackPlanner generates a sequence of AttackRequests from a goal and scan state.
// It converts an abstract goal (e.g. ACCESS_OTHER_USER_DATA) into concrete HTTP requests.
type AttackPlanner interface {
	// Plan generates a list of attack requests for the given goal.
	// It uses the scan's endpoint map, workflow states, and sessions to construct requests.
	Plan(ctx context.Context, in PlannerInput) ([]AttackRequest, error)
}

// PlannerInput is the context provided to an AttackPlanner.
type PlannerInput struct {
	ScanID     string
	GoalID     string
	GoalType   string
	TargetURL  string
	Sessions   []*Session         // available authenticated sessions
	Endpoints  []PlannerEndpoint  // discovered endpoints with parameter semantics
}

// PlannerEndpoint is an endpoint enriched with semantic parameter information.
type PlannerEndpoint struct {
	Method        string
	URL           string
	Params        []PlannerParam
	ResourceType  string // inferred type: user, order, file, admin
}

// PlannerParam describes a request parameter with its semantic meaning.
type PlannerParam struct {
	Name         string
	Location     string // query, body, path, header
	Value        string // observed value
	SemanticType string // user_id, resource_id, uuid, email, token, unknown
}

// AttackExecutor sends a prepared AttackRequest and returns the raw response.
// It is intentionally simple: it does not interpret results.
type AttackExecutor interface {
	// Execute sends the attack request and captures the response.
	Execute(ctx context.Context, req *AttackRequest) (*AttackResponse, error)
}

// AttackVerifier determines whether an attack result proves the goal was achieved.
// It compares the attack response against a baseline (the legitimate owner's response).
type AttackVerifier interface {
	// Verify compares the attack response to a baseline and returns a verdict.
	Verify(ctx context.Context, in VerifierInput) (*AttackResult, error)
}

// VerifierInput is all the information the verifier needs to make a determination.
type VerifierInput struct {
	Goal          string
	AttackReq     *AttackRequest
	AttackResp    *AttackResponse
	// Baseline: the same request made by the legitimate owner (for IDOR comparison).
	BaselineResp  *AttackResponse
	// Owner session used for baseline (to confirm what the data looks like for the owner).
	OwnerSession  *Session
}

// --- Default (no-op) Implementations ---
// These satisfy the interfaces and allow the orchestrator to compile and run
// while concrete implementations are built in later phases.

// NoopPlanner generates no attack requests. Replace with concrete implementation.
type NoopPlanner struct{}

func (p *NoopPlanner) Plan(_ context.Context, _ PlannerInput) ([]AttackRequest, error) {
	return nil, nil
}

// HTTPAttackExecutor is a concrete executor that uses a plain net/http client.
// It respects the Session's cookie jar and headers.
type HTTPAttackExecutor struct {
	DefaultTimeout time.Duration
}

func NewHTTPAttackExecutor() *HTTPAttackExecutor {
	return &HTTPAttackExecutor{DefaultTimeout: 15 * time.Second}
}

func (e *HTTPAttackExecutor) Execute(ctx context.Context, req *AttackRequest) (*AttackResponse, error) {
	client := req.Session.Client
	if client == nil {
		client = &http.Client{Timeout: e.DefaultTimeout}
	}

	var bodyReader *byteReader
	if len(req.Body) > 0 {
		bodyReader = &byteReader{data: req.Body, pos: 0}
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	for k, v := range req.Session.Headers {
		httpReq.Header.Set(k, v)
	}
	if req.ContentType != "" {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)
	body := make([]byte, 0, 65536)
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if readErr != nil {
			break
		}
		if len(body) > 512*1024 { // cap at 512KB
			break
		}
	}

	return &AttackResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		DurationMs: elapsed.Milliseconds(),
	}, nil
}

// NoopVerifier always returns INCONCLUSIVE. Replace with concrete implementation.
type NoopVerifier struct{}

func (v *NoopVerifier) Verify(_ context.Context, in VerifierInput) (*AttackResult, error) {
	return &AttackResult{
		Request:    in.AttackReq,
		Response:   in.AttackResp,
		Verdict:    VerdictInconclusive,
		Evidence:   "No verifier configured",
		ExecutedAt: time.Now(),
	}, nil
}

// byteReader is a minimal io.Reader wrapper around a byte slice.
type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, &eofError{}
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

type eofError struct{}

func (e *eofError) Error() string { return "EOF" }
