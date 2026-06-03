package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/parth/lastresort/internal/orchestrator"
	"github.com/parth/lastresort/internal/storage"
)

// RegisterRestRoutes mounts REST extension endpoints on the given mux.
// These expose features not yet encoded in the .proto file.
func (s *ScanServer) RegisterRestRoutes(mux *http.ServeMux) {
	// Phase 1
	mux.HandleFunc("/api/v1/hypotheses", s.handleListHypotheses)
	mux.HandleFunc("/api/v1/scan-modules", s.handleListScanModules)
	// Performance
	mux.HandleFunc("/api/v1/scan/performance", s.handleScanPerformance)
	// Phase 3
	mux.HandleFunc("/api/v1/workflow/states", s.handleListWorkflowStates)
	mux.HandleFunc("/api/v1/workflow/actions", s.handleListWorkflowActions)
	mux.HandleFunc("/api/v1/workflow/artifacts", s.handleListWorkflowArtifacts)
	mux.HandleFunc("/api/v1/workflow/sessions", s.handleListWorkflowSessions)
	// Phase 5
	mux.HandleFunc("/api/v1/goals", s.handleGoals)
	
	// Scan Event Pusher REST interface for dynamic log/screenshot streaming
	mux.HandleFunc("/api/v1/scan/event", s.handleScanEvent)
}

// handleListHypotheses responds to GET /api/v1/hypotheses?scan_id=...
func (s *ScanServer) handleListHypotheses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	hyps, err := s.DB.ListHypotheses(r.Context(), scanID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hyps == nil {
		hyps = []storage.Hypothesis{}
	}
	writeJSON(w, map[string]interface{}{"hypotheses": hyps})
}

// handleListScanModules responds to GET /api/v1/scan-modules?scan_id=...
func (s *ScanServer) handleListScanModules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		writeJSONError(w, http.StatusBadRequest, "scan_id is required")
		return
	}
	modules, err := s.DB.ListScanModules(r.Context(), scanID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if modules == nil {
		modules = []storage.ScanModuleRecord{}
	}
	writeJSON(w, map[string]interface{}{"modules": modules})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// --- Phase 3: Workflow Intelligence REST handlers ---

func (s *ScanServer) handleListWorkflowStates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		writeJSONError(w, http.StatusBadRequest, "scan_id is required")
		return
	}
	states, err := s.DB.ListWorkflowStates(r.Context(), scanID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if states == nil {
		states = []storage.WorkflowState{}
	}
	writeJSON(w, map[string]interface{}{"states": states})
}

func (s *ScanServer) handleListWorkflowActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		writeJSONError(w, http.StatusBadRequest, "scan_id is required")
		return
	}
	actions, err := s.DB.ListWorkflowActions(r.Context(), scanID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if actions == nil {
		actions = []storage.WorkflowAction{}
	}
	writeJSON(w, map[string]interface{}{"actions": actions})
}

func (s *ScanServer) handleListWorkflowArtifacts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		writeJSONError(w, http.StatusBadRequest, "scan_id is required")
		return
	}
	artifacts, err := s.DB.ListWorkflowArtifacts(r.Context(), scanID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if artifacts == nil {
		artifacts = []storage.WorkflowArtifact{}
	}
	writeJSON(w, map[string]interface{}{"artifacts": artifacts})
}

func (s *ScanServer) handleListWorkflowSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		writeJSONError(w, http.StatusBadRequest, "scan_id is required")
		return
	}
	sessions, err := s.DB.ListWorkflowSessions(r.Context(), scanID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sessions == nil {
		sessions = []storage.WorkflowSession{}
	}
	writeJSON(w, map[string]interface{}{"sessions": sessions})
}

// --- Phase 5: Goals REST handlers ---

// handleGoals handles GET /api/v1/goals?scan_id=...
// and POST /api/v1/goals to create a new goal.
func (s *ScanServer) handleGoals(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		scanID := r.URL.Query().Get("scan_id")
		if scanID == "" {
			writeJSONError(w, http.StatusBadRequest, "scan_id is required")
			return
		}
		goals, err := s.DB.ListGoals(r.Context(), scanID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if goals == nil {
			goals = []storage.AttackGoal{}
		}
		writeJSON(w, map[string]interface{}{"goals": goals})

	case http.MethodPost:
		var req struct {
			ScanID               string `json:"scan_id"`
			GoalType             string `json:"goal_type"`
			Description          string `json:"description"`
			SuccessCriteria      string `json:"success_criteria"`
			VerificationCriteria string `json:"verification_criteria"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.ScanID == "" || req.GoalType == "" || req.Description == "" {
			writeJSONError(w, http.StatusBadRequest, "scan_id, goal_type, and description are required")
			return
		}
		id, err := s.DB.SaveGoal(r.Context(), req.ScanID, storage.GoalType(req.GoalType), req.Description, req.SuccessCriteria, req.VerificationCriteria)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]interface{}{"goal_id": id})

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleScanEvent handles POST /api/v1/scan/event to push events to the scan global broker
func (s *ScanServer) handleScanEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		ScanID    string                 `json:"scan_id"`
		EventType string                 `json:"event_type"`
		Data      map[string]interface{} `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.ScanID == "" || req.EventType == "" {
		writeJSONError(w, http.StatusBadRequest, "scan_id and event_type are required")
		return
	}

	event := orchestrator.Event{
		ScanID:    req.ScanID,
		Type:      orchestrator.EventType(req.EventType),
		Timestamp: time.Now(),
		Data:      req.Data,
	}

	orchestrator.GlobalBroker.Publish(event)
	writeJSON(w, map[string]interface{}{"success": true})
}

// handleScanPerformance responds to GET /api/v1/scan/performance?scan_id=...
func (s *ScanServer) handleScanPerformance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		writeJSONError(w, http.StatusBadRequest, "scan_id is required")
		return
	}
	metrics, err := s.DB.GetScanPerformance(r.Context(), scanID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, metrics)
}
