package orchestrator

import (
	"sync"
	"time"
)

// EventType specifies the classification of scan events
type EventType string

const (
	EventScanStarted      EventType = "scan.started"
	EventPhaseStarted     EventType = "phase.started"
	EventPhaseCompleted   EventType = "phase.completed"
	EventFindingNew       EventType = "finding.new"
	EventProgress         EventType = "progress.update"
	EventScanCompleted    EventType = "scan.completed"
)

// Event holds details representing a single orchestration status change
type Event struct {
	ScanID    string
	Type      EventType
	Timestamp time.Time
	Data      map[string]interface{}
}

// EventBroker coordinates subscription logic for streaming RPC endpoints
type EventBroker struct {
	mu          sync.RWMutex
	subscribers map[string][]chan Event
}

// GlobalBroker is the default system-wide event channel
var GlobalBroker = &EventBroker{
	subscribers: make(map[string][]chan Event),
}

// Subscribe returns an active channel for reading events related to a scan
func (b *EventBroker) Subscribe(scanID string) chan Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	ch := make(chan Event, 100)
	b.subscribers[scanID] = append(b.subscribers[scanID], ch)
	return ch
}

// Unsubscribe closes and registers the removal of a subscription channel
func (b *EventBroker) Unsubscribe(scanID string, ch chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	subs, exists := b.subscribers[scanID]
	if !exists {
		return
	}

	for i, sub := range subs {
		if sub == ch {
			close(ch)
			b.subscribers[scanID] = append(subs[:i], subs[i+1:]...)
			break
		}
	}

	if len(b.subscribers[scanID]) == 0 {
		delete(b.subscribers, scanID)
	}
}

// Publish distributes an event to all matching scan subscribers
func (b *EventBroker) Publish(ev Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	subs := b.subscribers[ev.ScanID]
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
			// Prevent slow consumers from blocking orchestration pipeline
		}
	}
}
