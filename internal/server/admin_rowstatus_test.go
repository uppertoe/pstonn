package server

import (
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// The prod config that surfaced the bug: keep-warm every 8h, idle window 12h,
// safety margin 1h — so the renew deadline is 11h, and a healthy scheduled session
// (warmed within the last 8h) must NOT read as stale in the 6–8h gap the old fixed
// 6h constant flagged.
func TestTenantRowStatus(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	const maxAge = 90 * 24 * time.Hour
	const warmStaleAfter = 11 * time.Hour // idleWindow(12h) - safetyMargin(1h)

	linked := func(warmedAgo, activeAgo time.Duration) store.AdminAccount {
		return store.AdminAccount{
			Owner:      "u@example.com",
			Linked:     true,
			LinkedAt:   now.Add(-120 * 24 * time.Hour), // old link; idleSince must use LastActive
			LastActive: now.Add(-activeAgo),
			WarmedAt:   now.Add(-warmedAgo),
		}
	}

	cases := []struct {
		name       string
		acct       store.AdminAccount
		keptWarm   bool
		wantStatus string
		wantAttn   bool
	}{
		{"not linked", store.AdminAccount{Owner: "x"}, false, "unlinked", false},
		{"scheduled, warmed 7h ago (in old 6-8h false-positive gap)", linked(7*time.Hour, time.Hour), true, "ok", false},
		{"scheduled, warmed 10h ago (overdue but pre-deadline)", linked(10*time.Hour, time.Hour), true, "ok", false},
		{"scheduled, warmed 12h ago (past renew deadline)", linked(12*time.Hour, time.Hour), true, "stale", true},
		{"unscheduled, warmed 3 days ago (expected, not a fault)", linked(72*time.Hour, time.Hour), false, "ok", false},
		{"re-link due (idle beyond maxAge) outranks warm state", linked(time.Hour, maxAge+time.Hour), true, "relink", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, _, attn := tenantRowStatus(tc.acct, tc.keptWarm, now, maxAge, warmStaleAfter)
			if status != tc.wantStatus || attn != tc.wantAttn {
				t.Fatalf("got (%q, attn=%v), want (%q, attn=%v)", status, attn, tc.wantStatus, tc.wantAttn)
			}
		})
	}
}

// A transient tenant failure leaves an "error" as the newest apply_log row for up to
// 90 days. It must only read as a live fault while the permit is still failing (streak
// > 0); once settled (streak 0, plate back in place) it is cleared history — this is
// one user's case, where an old blip kept the panel showing "needs attention".
func TestApplyFailureState(t *testing.T) {
	cases := []struct {
		status      string
		maxStreak   int
		wantBad     bool
		wantCleared bool
	}{
		{"success", 0, false, false},
		{"error", 3, true, false},    // still failing → live fault
		{"error", 0, false, true},    // settled transient failure → cleared history, no alarm
		{"changed", 0, false, false}, // external portal edit → informational, never a fault
		{"", 0, false, false},
	}
	for _, tc := range cases {
		bad, cleared := applyFailureState(tc.status, tc.maxStreak)
		if bad != tc.wantBad || cleared != tc.wantCleared {
			t.Errorf("applyFailureState(%q, %d) = (bad=%v, cleared=%v), want (bad=%v, cleared=%v)",
				tc.status, tc.maxStreak, bad, cleared, tc.wantBad, tc.wantCleared)
		}
	}
}
