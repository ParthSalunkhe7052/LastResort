package attack

import "time"

// JournalEntry records a single step in a multi-step attack workflow.
type JournalEntry struct {
	Timestamp time.Time     `json:"timestamp"`
	Step      int           `json:"step"`
	Goal      string        `json:"goal"` // e.g. "Find login form"
	Action    string        `json:"action"`
	Selector  string        `json:"selector,omitempty"`
	Value     string        `json:"value,omitempty"`
	Reasoning string        `json:"reasoning"` // AI's reasoning for this action
	Result    *ActionResult `json:"result"`
	Verdict   AttackVerdict `json:"verdict,omitempty"` // CONFIRMED, FAILED, etc.
}

// SessionJournal provides persistent attack memory.
// Kept in-memory during scan and persisted to SQLite.
type SessionJournal struct {
	ScanID      string         `json:"scan_id"`
	Entries     []JournalEntry `json:"entries"`
	CurrentStep int            `json:"current_step"`
}
