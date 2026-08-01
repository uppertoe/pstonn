package server

import (
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
)

// The /status council section is what the watchdog alerts on, so the mapping from
// the client's Stats must be exact: rate windows, pushback diagnostics, breaker
// state (remaining pause in whole seconds), and persistence health.
func TestCouncilStatusFrom(t *testing.T) {
	at := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	cs := councilStatusFrom(parking.Stats{
		LastMinute: 5, Last5Min: 20, Pushback: 3,
		BreakerOpen: true, BreakerFor: 90 * time.Second,
		LastPushbackAt: at, LastPushbackStatus: 429, LastPushbackRef: "AZ-REF-1",
		PersistOK: false, PersistError: "disk full",
	})
	if cs.Requests1m != 5 || cs.Requests5m != 20 || cs.PushbacksTotal != 3 {
		t.Errorf("rate/pushback totals mismapped: %+v", cs)
	}
	if !cs.BreakerOpen || cs.BreakerRemainingS != 90 {
		t.Errorf("breaker state mismapped: open=%v remaining=%d", cs.BreakerOpen, cs.BreakerRemainingS)
	}
	if cs.LastPushbackAt != "2026-08-01T09:00:00Z" || cs.LastPushbackStatus != 429 || cs.LastPushbackRef != "AZ-REF-1" {
		t.Errorf("pushback diagnostics mismapped: %+v", cs)
	}
	if cs.PersistOK || cs.PersistError != "disk full" {
		t.Errorf("persist health mismapped: ok=%v err=%q", cs.PersistOK, cs.PersistError)
	}

	// Healthy defaults: no pushback seen, persistence intact, breaker closed.
	clean := councilStatusFrom(parking.Stats{PersistOK: true})
	if clean.BreakerOpen || clean.LastPushbackAt != "" || !clean.PersistOK {
		t.Errorf("clean snapshot should be quiet: %+v", clean)
	}
}
