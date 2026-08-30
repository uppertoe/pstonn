package store

import (
	"context"
	"testing"
	"time"
)

// TestPermitActiveConfirmedAt: the council-confirmed stamp is what lets a cold
// schedule visit show the plate with its tick instead of a spinner, so every
// write path that records a council-confirmed plate must set it, the agree-only
// touch must be a guarded, monotonic CAS, and a database that predates the
// column must read as "never confirmed" rather than fail.
func TestPermitActiveConfirmedAt(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const owner = "alice@example.com"
	id, err := s.UpsertPermit(ctx, owner, "14576", "14", "Front")
	if err != nil {
		t.Fatal(err)
	}

	// Fresh row: nothing confirmed yet.
	p, err := s.GetPermit(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !p.ActiveConfirmedAt.IsZero() {
		t.Fatalf("new permit ActiveConfirmedAt = %v, want zero", p.ActiveConfirmedAt)
	}

	// A confirmed apply stamps it.
	before := time.Now().Add(-2 * time.Second)
	if err := s.SetPermitActive(ctx, id, "ABC123"); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetPermit(ctx, id)
	if p.ActiveConfirmedAt.Before(before) {
		t.Fatalf("SetPermitActive left ActiveConfirmedAt = %v, want >= %v", p.ActiveConfirmedAt, before)
	}
	stamped := p.ActiveConfirmedAt

	// Touch: an older reading never moves the stamp backwards...
	if err := s.TouchPermitConfirmed(ctx, id, "ABC123", stamped.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if p, _ = s.GetPermit(ctx, id); !p.ActiveConfirmedAt.Equal(stamped) {
		t.Fatalf("older touch moved the stamp to %v (was %v)", p.ActiveConfirmedAt, stamped)
	}
	// ...a reading for a DIFFERENT plate vouches for nothing...
	later := stamped.Add(time.Hour)
	if err := s.TouchPermitConfirmed(ctx, id, "XYZ789", later); err != nil {
		t.Fatal(err)
	}
	if p, _ = s.GetPermit(ctx, id); !p.ActiveConfirmedAt.Equal(stamped) {
		t.Fatalf("touch for another plate moved the stamp to %v", p.ActiveConfirmedAt)
	}
	// ...and a newer reading that agrees advances it.
	if err := s.TouchPermitConfirmed(ctx, id, "ABC123", later); err != nil {
		t.Fatal(err)
	}
	if p, _ = s.GetPermit(ctx, id); !p.ActiveConfirmedAt.Equal(later) {
		t.Fatalf("agreeing touch left the stamp at %v, want %v", p.ActiveConfirmedAt, later)
	}

	// Adopting a council reading via the CAS stamps it too (and only when it lands).
	if ok, err := s.SetPermitActiveIfUnchanged(ctx, id, "STALE", "NEW111"); err != nil || ok {
		t.Fatalf("CAS from a stale belief landed (ok=%v err=%v)", ok, err)
	}
	if p, _ = s.GetPermit(ctx, id); !p.ActiveConfirmedAt.Equal(later) {
		t.Fatalf("a lost CAS moved the stamp to %v", p.ActiveConfirmedAt)
	}
	if ok, err := s.SetPermitActiveIfUnchanged(ctx, id, "ABC123", "NEW111"); err != nil || !ok {
		t.Fatalf("CAS from the current belief did not land (ok=%v err=%v)", ok, err)
	}
	// (later sits an hour ahead of the clock, so "stamped now" means it moved off later.)
	if p, _ = s.GetPermit(ctx, id); p.ActiveRegistration != "NEW111" || p.ActiveConfirmedAt.Equal(later) || p.ActiveConfirmedAt.Before(before) {
		t.Fatalf("after adopt: plate=%q confirmed=%v, want NEW111 stamped now", p.ActiveRegistration, p.ActiveConfirmedAt)
	}

	// The lazy column add is idempotent across the store's other permit readers.
	if _, err := s.ListPermitsFor(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PermitInTenant(ctx, p.TenantID, "14576"); err != nil {
		t.Fatal(err)
	}
}

// TestPermitConfirmedAtColumnBackfill: a database opened without the column
// (the pre-upgrade shape) gains it on first permit access rather than failing.
func TestPermitConfirmedAtColumnBackfill(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	// Reach the old shape: drop the column the lazy ensure added, then forget that
	// this store already ran the ensure.
	if _, err := s.ListPermits(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE permit DROP COLUMN active_confirmed_at`); err != nil {
		t.Fatal(err)
	}
	permitSchemaOnce.Delete(s)
	id, err := s.UpsertPermit(ctx, "bob@example.com", "9", "1", "Back")
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.GetPermit(ctx, id)
	if err != nil {
		t.Fatalf("read after dropping the column: %v", err)
	}
	if !p.ActiveConfirmedAt.IsZero() {
		t.Fatalf("backfilled column read as %v, want zero", p.ActiveConfirmedAt)
	}
}
