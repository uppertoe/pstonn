package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/store"
)

// notifyAddedDriver emails the driver of the car just put ON the permit — but
// only a SAVED car with a contact email whose household left the per-car toggle
// on, and only a deliverable address.
func TestNotifyAddedDriver(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	nf := &fakeNotifier{on: true}
	s := New(st, &fakeTenant{}, time.UTC, Options{Notifier: nf})
	const owner = "owner@example.com"
	p := model.Permit{ID: 1, Owner: owner}

	veh := map[ownerVehicle]model.VehicleInfo{
		{owner, 5}: {Registration: "NAN123", Email: "nanny@example.com", NotifyDriver: true},
		{owner, 6}: {Registration: "OFF123", Email: "off@example.com", NotifyDriver: false},
		{owner, 7}: {Registration: "NOEM123", Email: "", NotifyDriver: true},
	}

	reset := func() { nf.mu.Lock(); nf.added = nil; nf.mu.Unlock() }
	last := func() []string { nf.mu.Lock(); defer nf.mu.Unlock(); return append([]string(nil), nf.added...) }

	// Saved car, email set, toggle on -> the driver is notified.
	reset()
	s.notifyAddedDriver(ctx, p, "NAN123", veh)
	if got := last(); len(got) != 1 || got[0] != "nanny@example.com" {
		t.Fatalf("on+email: added=%v, want [nanny@example.com]", got)
	}

	// Toggle off -> silent.
	reset()
	s.notifyAddedDriver(ctx, p, "OFF123", veh)
	if got := last(); len(got) != 0 {
		t.Fatalf("toggle off must be silent, added=%v", got)
	}

	// No email -> silent.
	reset()
	s.notifyAddedDriver(ctx, p, "NOEM123", veh)
	if got := last(); len(got) != 0 {
		t.Fatalf("no email must be silent, added=%v", got)
	}

	// An ad-hoc plate (no saved vehicle) -> silent.
	reset()
	s.notifyAddedDriver(ctx, p, "ADHOC9", veh)
	if got := last(); len(got) != 0 {
		t.Fatalf("ad-hoc plate must be silent, added=%v", got)
	}

	// A suppressed (bounced/unsubscribed) address -> skipped.
	reset()
	if err := st.SuppressAddress(ctx, "nanny@example.com", store.SuppressUnsubscribed, "test"); err != nil {
		t.Fatal(err)
	}
	s.notifyAddedDriver(ctx, p, "NAN123", veh)
	if got := last(); len(got) != 0 {
		t.Fatalf("suppressed address must be skipped, added=%v", got)
	}
}
