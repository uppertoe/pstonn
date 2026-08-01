package server

import (
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
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

// The warm-margin aggregation is what lets the watchdog see a reconnect backlog
// forming before sessions lapse. estimated margin = idleWindow - age.
func TestCouncilSessionCounts(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	const warmInterval, idleWindow = 105 * time.Minute, 10 * time.Hour
	mk := func(age time.Duration) store.CouncilSession {
		return store.CouncilSession{Cookie: "c", UpdatedAt: now.Add(-age)}
	}
	sessions := []store.CouncilSession{
		mk(10 * time.Minute),             // freshly warmed: healthy
		mk(2 * time.Hour),                // past the 105m warm interval: overdue, still "warm" (<6h)
		mk(9*time.Hour + 30*time.Minute), // margin 30m: overdue AND near the cliff (worst)
		{Cookie: ""},                     // unlinked: ignored
	}
	sc := councilSessionCounts(sessions, now, warmInterval, idleWindow)
	if sc.Linked != 3 {
		t.Errorf("linked = %d, want 3", sc.Linked)
	}
	if sc.Warm != 2 { // the 10m and 2h sessions are within 6h
		t.Errorf("warm = %d, want 2", sc.Warm)
	}
	if sc.OverdueWarm != 2 { // 2h and 9h30m are both past 105m
		t.Errorf("overdue_warm = %d, want 2", sc.OverdueWarm)
	}
	if sc.NearExpiry != 1 { // only 9h30m has margin < 105m
		t.Errorf("near_expiry = %d, want 1", sc.NearExpiry)
	}
	if sc.MinMarginSeconds == nil || *sc.MinMarginSeconds != 30*60 {
		t.Errorf("min_margin_seconds = %v, want 1800 (30m)", sc.MinMarginSeconds)
	}

	// No linked sessions: no margin reported at all.
	empty := councilSessionCounts([]store.CouncilSession{{Cookie: ""}}, now, warmInterval, idleWindow)
	if empty.Linked != 0 || empty.MinMarginSeconds != nil {
		t.Errorf("empty fleet should report nothing: %+v", empty)
	}
}
