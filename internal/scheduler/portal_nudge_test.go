package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// quietDriftRig builds an owner with ONE unscheduled permit whose council record
// has moved on: the silent-adopt path, which says nothing to the household.
func quietDriftRig(t *testing.T, owner, tenantID, believed, atCouncil string) (*store.Store, *fakeNotifier, *fakeTenant, *Scheduler, int64) {
	t.Helper()
	ctx := context.Background()
	st := newStore(t)
	seedSession(t, st, owner)
	pid, err := st.UpsertPermit(ctx, owner, tenantID, "14", "Permit")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetPermitActive(ctx, pid, believed); err != nil {
		t.Fatal(err)
	}
	fc := &fakeTenant{}
	fc.setCurrent(tenantID, atCouncil)
	nf := &fakeNotifier{on: true, admin: true}
	return st, nf, fc, New(st, fc, time.UTC, Options{Notifier: nf}), pid
}

// The household that changes its plate at the council and never uses p.stonn is
// told ONCE that it could have. Drift itself stays silent, as it must.
func TestSilentAdoptSendsThePortalNoteOnce(t *testing.T) {
	ctx := context.Background()
	const owner, tenantID = "portal@example.com", "portal-1"
	_, nf, fc, s, _ := quietDriftRig(t, owner, tenantID, "OLD111", "NEW222")

	if err := s.checkDrift(ctx, owner, ""); err != nil {
		t.Fatal(err)
	}
	if got := nf.portalNudgedSnap(); len(got) != 1 || got[0] != owner+"|NEW222" {
		t.Fatalf("portal notes = %v, want one naming NEW222", got)
	}
	nf.mu.Lock()
	drifts := len(nf.drifts)
	nf.mu.Unlock()
	if drifts != 0 {
		t.Fatalf("drift notice sent on the silent path: %d", drifts)
	}

	// A second external change must not produce a second note: the message itself
	// promises this is the only time p.stonn raises it.
	fc.setCurrent(tenantID, "THIRD33")
	if err := s.checkDrift(ctx, owner, ""); err != nil {
		t.Fatal(err)
	}
	if got := nf.portalNudgedSnap(); len(got) != 1 {
		t.Fatalf("portal notes after a second change = %v, want still one", got)
	}
}

// Someone who has already used p.stonn to put a plate on the permit is not the
// audience: the note's whole premise is that they have not tried it.
func TestSilentAdoptSkipsTheNoteWhenTheAppHasBeenUsed(t *testing.T) {
	ctx := context.Background()
	const owner, tenantID = "portal-used@example.com", "portal-2"
	st, nf, _, s, pid := quietDriftRig(t, owner, tenantID, "OLD111", "NEW222")
	if err := st.RecordApply(ctx, pid, "MINE111", "override", "success", ""); err != nil {
		t.Fatal(err)
	}

	if err := s.checkDrift(ctx, owner, ""); err != nil {
		t.Fatal(err)
	}
	if got := nf.portalNudgedSnap(); len(got) != 0 {
		t.Fatalf("portal notes = %v, want none for a household that has used the app", got)
	}
}

// A cleared plate carries nothing to show, so it is not an occasion for the note.
func TestSilentAdoptOfAClearedPlateSendsNoNote(t *testing.T) {
	ctx := context.Background()
	const owner, tenantID = "portal-clear@example.com", "portal-3"
	_, nf, _, s, _ := quietDriftRig(t, owner, tenantID, "OLD111", "")

	if err := s.checkDrift(ctx, owner, ""); err != nil {
		t.Fatal(err)
	}
	if got := nf.portalNudgedSnap(); len(got) != 0 {
		t.Fatalf("portal notes = %v, want none when the plate was cleared", got)
	}
}

// A failed send leaves the one shot unspent, so a later round can try again.
func TestPortalNoteRetriesAfterAFailedSend(t *testing.T) {
	ctx := context.Background()
	const owner, tenantID = "portal-retry@example.com", "portal-4"
	_, nf, fc, s, _ := quietDriftRig(t, owner, tenantID, "OLD111", "NEW222")
	nf.portalErr = errors.New("smtp down")

	if err := s.checkDrift(ctx, owner, ""); err != nil {
		t.Fatal(err)
	}
	nf.portalErr = nil
	fc.setCurrent(tenantID, "THIRD33")
	if err := s.checkDrift(ctx, owner, ""); err != nil {
		t.Fatal(err)
	}
	if got := nf.portalNudgedSnap(); len(got) != 2 {
		t.Fatalf("portal notes = %v, want the failed send retried on the next round", got)
	}
}
