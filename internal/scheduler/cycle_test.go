package scheduler

import (
	"context"
	"testing"
	"time"
)

// TestReconcileFollowsTheCycleWeek: with a two-week cycle rostering different
// cars on the same weekday, the write path must apply the car of the week the
// clock is IN — and crossing the Sunday boundary into the other week switches
// it. Driven entirely by the injected clock.
func TestReconcileFollowsTheCycleWeek(t *testing.T) {
	ctx := context.Background()
	const owner, tenantID = "cycle@example.com", "cycle-permit"
	st := newStore(t)
	seedSession(t, st, owner)
	vehA, err := st.CreateVehicle(ctx, owner, "AAA111", "Week-zero car", "")
	if err != nil {
		t.Fatal(err)
	}
	vehB, err := st.CreateVehicle(ctx, owner, "BBB222", "Week-one car", "")
	if err != nil {
		t.Fatal(err)
	}
	pid, err := st.UpsertPermit(ctx, owner, tenantID, "14", "Permit")
	if err != nil {
		t.Fatal(err)
	}
	// Wednesday 2026-09-09 UTC sits in the week anchored 2026-09-06 (week 0).
	base := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	if _, err := st.AddCycleWeek(ctx, owner, pid, "2026-09-06"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRule(ctx, pid, 0, time.Wednesday, vehA); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRule(ctx, pid, 1, time.Wednesday, vehB); err != nil {
		t.Fatal(err)
	}

	fc := &fakeTenant{}
	fc.setCurrent(tenantID, "")
	s := New(st, fc, time.UTC, Options{Notifier: &fakeNotifier{on: true, admin: true}})
	s.clock = func() time.Time { return base }

	s.reconcileAll(ctx)
	if got := fc.lastReg(); got != "AAA111" {
		t.Fatalf("week 0 Wednesday applied %q, want AAA111", got)
	}

	// One week later the cycle is in week 1: the SAME weekday now belongs to the
	// other car. This is the write an old, cycle-blind binary would get wrong.
	s.clock = func() time.Time { return base.AddDate(0, 0, 7) }
	s.reconcileAll(ctx)
	if got := fc.lastReg(); got != "BBB222" {
		t.Fatalf("week 1 Wednesday applied %q, want BBB222", got)
	}

	// And a fortnight after base it wraps back to week 0.
	fc.setCurrent(tenantID, "") // clear so the wrap needs a fresh write
	s.clock = func() time.Time { return base.AddDate(0, 0, 14) }
	s.reconcileAll(ctx)
	if got := fc.lastReg(); got != "AAA111" {
		t.Fatalf("wrapped Wednesday applied %q, want AAA111", got)
	}
}
