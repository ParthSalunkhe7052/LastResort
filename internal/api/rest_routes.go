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
	mux.HandleFunc("/api/v1/scan-modules", s.handleListScanModules)
	mux.HandleFunc("/api/v1/scan/performance", s.handleScanPerformance)
	mux.HandleFunc("/api/v1/scan/event", s.handleScanEvent)
	mux.HandleFunc("/api/v1/attack-metrics", s.handleAttackMetrics)
	mux.HandleFunc("/api/v1/verifications", s.handleListVerifications)
	mux.HandleFunc("/api/v1/replays", s.handleListReplays)
	mux.HandleFunc("/api/v1/journal", s.handleListJournal)
	mux.HandleFunc("/api/v1/settings", s.handleSettings)
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

// ─── Phase 2: Verification Engine REST Handlers ─────────────────────────────────

// handleAttackMetrics responds to GET /api/v1/attack-metrics?scan_id=...
// Returns live attack execution/verification/failure counters.
func (s *ScanServer) handleAttackMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		writeJSONError(w, http.StatusBadRequest, "scan_id is required")
		return
	}
	metrics, err := s.DB.GetAttackMetrics(r.Context(), scanID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, metrics)
}

// handleListVerifications responds to GET /api/v1/verifications?scan_id=...
// Returns all VerificationResult records for a scan — proof that attacks were verified.
func (s *ScanServer) handleListVerifications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		writeJSONError(w, http.StatusBadRequest, "scan_id is required")
		return
	}
	verifications, err := s.DB.ListVerificationsForScan(r.Context(), scanID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if verifications == nil {
		verifications = []*storage.StoredVerification{}
	}
	writeJSON(w, map[string]interface{}{"verifications": verifications, "count": len(verifications)})
}

// handleListReplays responds to GET /api/v1/replays?scan_id=...
// Returns attack replay records — exact step sequences from real browser execution.
func (s *ScanServer) handleListReplays(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		writeJSONError(w, http.StatusBadRequest, "scan_id is required")
		return
	}
	replays, err := s.DB.ListReplaysForScan(r.Context(), scanID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if replays == nil {
		replays = []*storage.AttackReplay{}
	}
	writeJSON(w, map[string]interface{}{"replays": replays, "count": len(replays)})
}

// handleListJournal responds to GET /api/v1/journal?scan_id=...
// Returns the session journal for a scan — every browser action taken during attack.
func (s *ScanServer) handleListJournal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		writeJSONError(w, http.StatusBadRequest, "scan_id is required")
		return
	}
	entries, err := s.DB.ListJournalEntries(r.Context(), scanID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []*storage.JournalEntry{}
	}
	writeJSON(w, map[string]interface{}{"journal": entries, "count": len(entries)})
}

// handleSettings handles GET and POST on /api/v1/settings
func (s *ScanServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings, err := s.DB.GetAllSettings(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Fallbacks
		if _, ok := settings["ai_provider"]; !ok {
			settings["ai_provider"] = "gemini"
		}
		if _, ok := settings["gemini_model"]; !ok {
			settings["gemini_model"] = "gemini-3.5-flash"
		}
		writeJSON(w, map[string]interface{}{"settings": settings})
	case http.MethodPost:
		var req struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Key == "" {
			writeJSONError(w, http.StatusBadRequest, "key is required")
			return
		}
		if err := s.DB.SaveSetting(r.Context(), req.Key, req.Value); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]interface{}{"success": true})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
