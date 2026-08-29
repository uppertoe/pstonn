package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// twoPermits sets up one account with two permits, each holding one booking.
func twoPermits(t *testing.T) (st *Store, owner string, permitA, permitB, ovA, ovB int64) {
	t.Helper()
	var err error
	st, err = OpenSQLite(filepath.Join(t.TempDir(), "ov.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	owner = "owner@example.com"

	vehID, err := st.CreateVehicle(ctx, owner, "ABC123", "Car", "")
	if err != nil {
		t.Fatalf("vehicle: %v", err)
	}
	for i, cid := range []string{"council-A", "council-B"} {
		p, err := st.UpsertPermit(ctx, owner, cid, "type", "Permit "+cid)
		if err != nil {
			t.Fatalf("permit %d: %v", i, err)
		}
		start := time.Now().Add(-time.Hour)
		ov, err := st.CreateOverride(ctx, p, vehID, start, nil, owner)
		if err != nil {
			t.Fatalf("override %d: %v", i, err)
		}
		if i == 0 {
			permitA, ovA = p, ov
		} else {
			permitB, ovB = p, ov
		}
	}
	return st, owner, permitA, permitB, ovA, ovB
}

// The delete route is /permits/{id}/overrides/{oid}/delete. With only an owner
// predicate, an {oid} belonging to a DIFFERENT permit of the same account was deleted
// anyway while the response re-rendered permit {id} — so a booking disappeared from a
// card the user was not looking at, with nothing on screen to say so.
func TestDeleteOverrideIsScopedToItsPermit(t *testing.T) {
	st, owner, permitA, permitB, _, ovB := twoPermits(t)
	ctx := context.Background()

	// Permit B's booking, addressed through permit A.
	deleted, err := st.DeleteOverrideOnPermit(ctx, owner, permitA, ovB)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deleted {
		t.Fatal("a booking on another permit was deleted through this permit's URL")
	}
	ovs, err := st.ListOverrides(ctx, permitB, time.Time{})
	if err != nil {
		t.Fatalf("list B: %v", err)
	}
	if len(ovs) != 1 {
		t.Fatalf("permit B has %d bookings, want its own still present", len(ovs))
	}
}

func TestDeleteOverrideOnItsOwnPermitWorks(t *testing.T) {
	st, owner, permitA, _, ovA, _ := twoPermits(t)
	ctx := context.Background()

	deleted, err := st.DeleteOverrideOnPermit(ctx, owner, permitA, ovA)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !deleted {
		t.Fatal("the permit's own booking should have been deleted")
	}
	if ovs, _ := st.ListOverrides(ctx, permitA, time.Time{}); len(ovs) != 0 {
		t.Fatalf("permit A still has %d bookings", len(ovs))
	}
}

// The bool is what lets the handler stay silent about a miss. Without it the handler
// wrote an audit row and kicked the scheduler for an id that never existed, which is
// replayable to bury a household's real activity under invented entries.
func TestDeleteOverrideReportsAMiss(t *testing.T) {
	st, owner, permitA, _, _, _ := twoPermits(t)
	ctx := context.Background()

	deleted, err := st.DeleteOverrideOnPermit(ctx, owner, permitA, 999999)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deleted {
		t.Fatal("deleting a nonexistent booking must report that nothing went")
	}
}

// Cross-account remains impossible, which the owner predicate already guaranteed.
func TestDeleteOverrideStillRefusesAnotherAccount(t *testing.T) {
	st, _, permitA, _, ovA, _ := twoPermits(t)
	ctx := context.Background()

	deleted, err := st.DeleteOverrideOnPermit(ctx, "attacker@example.com", permitA, ovA)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deleted {
		t.Fatal("another account deleted this household's booking")
	}
}
