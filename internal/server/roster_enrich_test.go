package server

import (
	"context"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// TestEnrichRoster pins the model-level half of the outage-roster policy: who
// stays in (live permits, stamped with their next due write), who stays in
// unstamped (live permit, nothing scheduled — the long-outage backstop's
// audience), and who drops out (every permit dead: an outage can't break a
// cancelled permit, and their address is PII the watchdog needn't hold).
func TestEnrichRoster(t *testing.T) {
	ctx := context.Background()
	s := newAuthzServer(t) // DisplayLocation = UTC, so midnights are UTC midnights

	// scheduled@: a permit whose roster changes car at EVERY midnight (a distinct
	// vehicle per weekday), so whatever day the test runs, the next write is the
	// next UTC midnight.
	pid, err := s.store.UpsertPermit(ctx, "scheduled@example.com", "P-sched", "14", "VPP1")
	if err != nil {
		t.Fatal(err)
	}
	for wd := time.Sunday; wd <= time.Saturday; wd++ {
		vid, verr := s.store.CreateVehicle(ctx, "scheduled@example.com",
			"CAR"+string(rune('0'+wd)), wd.String())
		if verr != nil {
			t.Fatal(verr)
		}
		if err := s.store.SetRule(ctx, pid, wd, vid); err != nil {
			t.Fatal(err)
		}
	}

	// static@: a live permit with nothing scheduled — stays in, unstamped.
	if _, err := s.store.UpsertPermit(ctx, "static@example.com", "P-static", "14", "VPP2"); err != nil {
		t.Fatal(err)
	}

	// dead@: holds only a cancelled permit — dropped entirely.
	if _, err := s.store.UpsertPermit(ctx, "dead@example.com", "P-dead", "14", "VPP3"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpdatePermitMeta(ctx, "dead@example.com", "P-dead", "Cancelled", "VPP3", "(A) 1st Visitor Permit", time.Time{}); err != nil {
		t.Fatal(err)
	}

	in := []store.RosterEntry{
		{Email: "scheduled@example.com"},
		{Email: "static@example.com", Ntfy: "static-topic"},
		{Email: "dead@example.com"},
	}
	out := s.enrichRoster(ctx, in)

	byEmail := map[string]store.RosterEntry{}
	for _, e := range out {
		byEmail[e.Email] = e
	}
	if _, ok := byEmail["dead@example.com"]; ok {
		t.Fatal("an owner with only a cancelled permit stayed in the outage roster")
	}
	if len(out) != 2 {
		t.Fatalf("roster = %+v, want scheduled@ and static@ only", out)
	}

	st, ok := byEmail["static@example.com"]
	if !ok || st.Ntfy != "static-topic" {
		t.Fatalf("static owner mangled: %+v", st)
	}
	if st.NextChangeAt != "" {
		t.Fatalf("nothing is scheduled for static@, yet NextChangeAt = %q", st.NextChangeAt)
	}

	sched, ok := byEmail["scheduled@example.com"]
	if !ok || sched.NextChangeAt == "" {
		t.Fatalf("scheduled owner missing their stamp: %+v", sched)
	}
	got, err := time.Parse(time.RFC3339, sched.NextChangeAt)
	if err != nil {
		t.Fatalf("NextChangeAt is not RFC3339: %q", sched.NextChangeAt)
	}
	now := time.Now().UTC()
	wantMidnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
	if !got.Equal(wantMidnight) {
		t.Fatalf("next write = %v, want the next UTC midnight %v", got, wantMidnight)
	}
}
