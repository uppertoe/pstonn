package server

import (
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
)

// The /status tenant section is what the watchdog alerts on, so the mapping from
// the client's Stats must be exact: rate windows, pushback diagnostics, breaker
// state (remaining pause in whole seconds), and persistence health.
func TestTenantStatusFrom(t *testing.T) {
	at := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	cs := tenantStatusFrom(parking.Stats{
		LastMinute: 5, Last5Min: 20, Pushback: 3,
		BreakerOpen: true, BreakerFor: 90 * time.Second,
		LastPushbackAt: at, LastPushbackStatus: 429, LastPushbackRef: "AZ-REF-1",
		PersistOK: false, PersistError: "disk full",
		LastPushbackSurface: "api",
		TruncatedGridAt:     at.Add(-time.Hour), TruncatedGridGot: 7, TruncatedGridWant: 12,
		State:         parking.StateBlocked,
		LastAttemptAt: at.Add(-time.Minute), LastSuccessAt: at.Add(-2 * time.Hour),
		ConsecutiveFailures: 4,
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

	// The two signals the watchdog alerts on. Both were recorded in parking.Stats and
	// silently dropped by this mapper, so the operator had no way to see either: a
	// paging change looked identical to a healthy account, and a refusal gave no clue
	// whether it hit login, auth or API traffic.
	if cs.LastPushbackSurface != "api" {
		t.Errorf("pushback surface dropped: %+v", cs)
	}
	if cs.TruncatedGridAt != "2026-08-01T08:00:00Z" || cs.TruncatedGridGot != 7 || cs.TruncatedGridWant != 12 {
		t.Errorf("truncated-grid signal dropped: at=%q got=%d want=%d",
			cs.TruncatedGridAt, cs.TruncatedGridGot, cs.TruncatedGridWant)
	}

	// The connector success clock — what lets the watchdog tell "scheduler alive"
	// from "scheduler's dependency usable". Dropping any of these regresses the
	// upstream-failure alert to user reports.
	if cs.State != parking.StateBlocked || cs.ConsecutiveFailures != 4 {
		t.Errorf("connector state mismapped: state=%q consec=%d", cs.State, cs.ConsecutiveFailures)
	}
	if cs.LastAttemptAt != "2026-08-01T08:59:00Z" || cs.LastSuccessAt != "2026-08-01T07:00:00Z" {
		t.Errorf("connector clock mismapped: attempt=%q success=%q", cs.LastAttemptAt, cs.LastSuccessAt)
	}

	// Healthy defaults: no pushback seen, persistence intact, breaker closed.
	clean := tenantStatusFrom(parking.Stats{PersistOK: true})
	if clean.BreakerOpen || clean.LastPushbackAt != "" || !clean.PersistOK {
		t.Errorf("clean snapshot should be quiet: %+v", clean)
	}
	if clean.TruncatedGridAt != "" || clean.LastPushbackSurface != "" {
		t.Errorf("a clean snapshot must not report truncation or a pushback surface: %+v", clean)
	}
	if clean.LastAttemptAt != "" || clean.LastSuccessAt != "" || clean.ConsecutiveFailures != 0 {
		t.Errorf("a clean snapshot must not invent a success clock: %+v", clean)
	}
}

// The warm-margin aggregation is what lets the watchdog see a reconnect backlog
// forming before sessions lapse. estimated margin = idleWindow - age; near_expiry
// uses a dedicated danger margin (NOT the warm interval); warm and overdue_warm
// split the fleet at the warm interval with no overlap.
func TestTenantSessionCounts(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	const warmInterval, idleWindow, warnMargin = 105 * time.Minute, 10 * time.Hour, 2 * time.Hour
	mk := func(owner string, age time.Duration) store.TenantSession {
		return store.TenantSession{Owner: owner, Cookie: "c", UpdatedAt: now.Add(-age)}
	}
	sessions := []store.TenantSession{
		mk("fresh", 10*time.Minute),                                         // freshly warmed: within the interval
		mk("stale", 2*time.Hour),                                            // past the 105m interval: overdue, margin 8h — not near
		mk("cliff", 9*time.Hour+30*time.Minute),                             // margin 30m: overdue AND near the cliff (worst)
		{Owner: "unsched", Cookie: "c", UpdatedAt: now.Add(-3 * time.Hour)}, // linked but NO schedule
		{Cookie: ""}, // unlinked: ignored entirely
	}
	scheduled := map[string]struct{}{"fresh": {}, "stale": {}, "cliff": {}}
	sc := tenantSessionCounts(sessions, now, warmInterval, idleWindow, warnMargin, scheduled)
	if sc.Linked != 4 { // every cookie'd session, including the unscheduled one
		t.Errorf("linked = %d, want 4", sc.Linked)
	}
	if sc.Warm != 1 { // only "fresh" is within the 105m interval
		t.Errorf("warm = %d, want 1", sc.Warm)
	}
	if sc.OverdueWarm != 2 { // "stale" and "cliff" are past 105m; "unsched" excluded
		t.Errorf("overdue_warm = %d, want 2", sc.OverdueWarm)
	}
	if sc.NearExpiry != 1 { // only "cliff" has margin < the 2h danger margin
		t.Errorf("near_expiry = %d, want 1", sc.NearExpiry)
	}
	if sc.MinMarginSeconds == nil || *sc.MinMarginSeconds != 30*60 {
		t.Errorf("min_margin_seconds = %v, want 1800 (30m)", sc.MinMarginSeconds)
	}

	// A longer warm interval must NOT drag near_expiry up: the danger margin is
	// independent, so a healthy session whose renew simply isn't due yet is not "near".
	scLong := tenantSessionCounts(sessions, now, 6*time.Hour, idleWindow, warnMargin, scheduled)
	if scLong.NearExpiry != 1 {
		t.Errorf("near_expiry = %d with a 6h warm interval, want 1 (still only the cliff session)", scLong.NearExpiry)
	}

	// An intentionally un-warmed session (no schedule) must not raise an alarm even
	// when it is well past the danger margin — its lapse is expected.
	cold := []store.TenantSession{{Owner: "cold", Cookie: "c", UpdatedAt: now.Add(-9*time.Hour - 45*time.Minute)}}
	scCold := tenantSessionCounts(cold, now, warmInterval, idleWindow, warnMargin, map[string]struct{}{})
	if scCold.Linked != 1 || scCold.NearExpiry != 0 || scCold.OverdueWarm != 0 || scCold.MinMarginSeconds != nil {
		t.Errorf("an unscheduled session must not drive warm-risk metrics: %+v", scCold)
	}

	// No linked sessions: no margin reported at all.
	empty := tenantSessionCounts([]store.TenantSession{{Cookie: ""}}, now, warmInterval, idleWindow, warnMargin, scheduled)
	if empty.Linked != 0 || empty.MinMarginSeconds != nil {
		t.Errorf("empty fleet should report nothing: %+v", empty)
	}
}
