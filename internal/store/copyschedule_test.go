package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// guestTokenIDOf reads an override's guest_token_id, which the model type does not
// carry — the column exists so revocation can sweep the bookings a guest link
// authorised, and nothing outside this package needs it.
func guestTokenIDOf(t *testing.T, st *Store, overrideID int64) int64 {
	t.Helper()
	var id int64
	if err := st.db.QueryRow(`SELECT guest_token_id FROM override WHERE id = ?`, overrideID).Scan(&id); err != nil {
		t.Fatalf("read guest_token_id for override %d: %v", overrideID, err)
	}
	return id
}

func copyStore(t *testing.T) *Store {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "copy.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// copyFixture builds an owner with two permits: src carries a roster and a live
// booking, dst is empty.
func copyFixture(t *testing.T, st *Store, owner string) (src, dst, vehID int64) {
	t.Helper()
	ctx := context.Background()
	var err error
	if vehID, err = st.CreateVehicle(ctx, owner, "SRC111", "Source car", ""); err != nil {
		t.Fatalf("vehicle: %v", err)
	}
	if src, err = st.UpsertPermit(ctx, owner, "src-permit", "14", "Source"); err != nil {
		t.Fatalf("src permit: %v", err)
	}
	if dst, err = st.UpsertPermit(ctx, owner, "dst-permit", "14", "Target"); err != nil {
		t.Fatalf("dst permit: %v", err)
	}
	if err := st.SetRule(ctx, src, 0, time.Monday, vehID); err != nil {
		t.Fatalf("rule: %v", err)
	}
	if err := st.SetRule(ctx, src, 0, time.Friday, vehID); err != nil {
		t.Fatalf("rule: %v", err)
	}
	return src, dst, vehID
}

func TestCopyScheduleCopiesRosterAndLiveBookings(t *testing.T) {
	ctx := context.Background()
	st := copyStore(t)
	const owner = "owner@example.com"
	src, dst, vehID := copyFixture(t, st, owner)

	now := time.Now().UTC()
	future := now.Add(4 * time.Hour)
	if _, err := st.CreateOverride(ctx, src, vehID, now.Add(-time.Hour), &future, owner); err != nil {
		t.Fatalf("live override: %v", err)
	}
	// An already-ended booking is history and must NOT be carried over: copying it
	// would put another permit's finished bookings into this one's activity.
	past := now.Add(-2 * time.Hour)
	if _, err := st.CreateOverride(ctx, src, vehID, now.Add(-3*time.Hour), &past, owner); err != nil {
		t.Fatalf("past override: %v", err)
	}

	n, err := st.CopySchedule(ctx, owner, src, dst, now)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if n == 0 {
		t.Error("copy reported nothing copied")
	}

	rules, err := st.ListRules(ctx, dst)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("target has %d rules, want the source's 2", len(rules))
	}
	ovs, err := st.ListOverrides(ctx, dst, time.Time{})
	if err != nil {
		t.Fatalf("list overrides: %v", err)
	}
	if len(ovs) != 1 {
		t.Fatalf("target has %d bookings, want only the live one (ended bookings are history)", len(ovs))
	}
}

// The source permit's schedule may include a booking a GUEST made, which carries the
// guest token that authorised it. The copy must not inherit that attribution: the copy
// is the owner's own deliberate act, and a household revoking that guest link later
// sweeps live overrides BY TOKEN — so an inherited token id would make the owner's
// copied booking vanish when an unrelated guest pass was revoked.
func TestCopyScheduleDropsGuestTokenAttribution(t *testing.T) {
	ctx := context.Background()
	st := copyStore(t)
	const owner = "owner@example.com"
	src, dst, vehID := copyFixture(t, st, owner)

	now := time.Now().UTC()
	future := now.Add(6 * time.Hour)
	// A guest-authorised booking on the source, carrying a (non-zero) token id.
	const fakeTokenID = 4242
	seedGuestToken(t, st, owner, src, fakeTokenID)
	if _, err := st.CreateGuestOverride(ctx, src, vehID, now.Add(-time.Minute), &future, "visitor@example.com", fakeTokenID); err != nil {
		t.Fatalf("guest override: %v", err)
	}

	if _, err := st.CopySchedule(ctx, owner, src, dst, now); err != nil {
		t.Fatalf("copy: %v", err)
	}

	ovs, err := st.ListOverrides(ctx, dst, time.Time{})
	if err != nil {
		t.Fatalf("list overrides: %v", err)
	}
	if len(ovs) != 1 {
		t.Fatalf("target has %d bookings, want 1", len(ovs))
	}
	// guest_token_id is a column, not a model field, so read it directly.
	if got := guestTokenIDOf(t, st, ovs[0].ID); got != 0 {
		t.Errorf("copied booking carries guest token %d, want 0 — otherwise revoking that guest pass would delete the owner's own copied booking", got)
	}
	// The source keeps its attribution; only the copy is unattributed.
	srcOvs, err := st.ListOverrides(ctx, src, time.Time{})
	if err != nil {
		t.Fatalf("list source overrides: %v", err)
	}
	if len(srcOvs) != 1 || guestTokenIDOf(t, st, srcOvs[0].ID) != fakeTokenID {
		t.Errorf("the source's attribution was disturbed: %+v", srcOvs)
	}
}

// A copy is a clean REPLACE, so whatever the target held must be gone.
func TestCopyScheduleReplacesTheTarget(t *testing.T) {
	ctx := context.Background()
	st := copyStore(t)
	const owner = "owner@example.com"
	src, dst, vehID := copyFixture(t, st, owner)

	// Give the target a roster of its own on a day the source does not use.
	if err := st.SetRule(ctx, dst, 0, time.Wednesday, vehID); err != nil {
		t.Fatalf("dst rule: %v", err)
	}
	now := time.Now().UTC()
	future := now.Add(3 * time.Hour)
	if _, err := st.CreateOverride(ctx, dst, vehID, now.Add(-time.Minute), &future, owner); err != nil {
		t.Fatalf("dst override: %v", err)
	}

	if _, err := st.CopySchedule(ctx, owner, src, dst, now); err != nil {
		t.Fatalf("copy: %v", err)
	}

	rules, _ := st.ListRules(ctx, dst)
	for _, r := range rules {
		if r.Weekday == time.Wednesday {
			t.Error("the target's own Wednesday rule survived a replace")
		}
	}
	if len(rules) != 2 {
		t.Errorf("target has %d rules after replace, want the source's 2", len(rules))
	}
	if ovs, _ := st.ListOverrides(ctx, dst, time.Time{}); len(ovs) != 0 {
		t.Errorf("the target's own live booking survived a replace: %+v", ovs)
	}
}

// Owner scoping is defence in depth behind the handler's own check, so it has to
// actually hold at the SQL layer.
func TestCopyScheduleIsOwnerScoped(t *testing.T) {
	ctx := context.Background()
	st := copyStore(t)
	const owner = "owner@example.com"
	src, dst, _ := copyFixture(t, st, owner)

	if _, err := st.CopySchedule(ctx, "attacker@example.com", src, dst, time.Now().UTC()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("copy as another account = %v, want ErrNotFound", err)
	}
	if rules, _ := st.ListRules(ctx, dst); len(rules) != 0 {
		t.Error("a refused copy still wrote rules to the target")
	}

	// A permit belonging to somebody else cannot be used as either end.
	foreign, err := st.UpsertPermit(ctx, "other@example.com", "other-permit", "14", "Theirs")
	if err != nil {
		t.Fatalf("foreign permit: %v", err)
	}
	if _, err := st.CopySchedule(ctx, owner, foreign, dst, time.Now().UTC()); !errors.Is(err, ErrNotFound) {
		t.Errorf("copying FROM another account's permit = %v, want ErrNotFound", err)
	}
	if _, err := st.CopySchedule(ctx, owner, src, foreign, time.Now().UTC()); !errors.Is(err, ErrNotFound) {
		t.Errorf("copying ONTO another account's permit = %v, want ErrNotFound", err)
	}
}

func TestCopyScheduleRefusesSelfCopy(t *testing.T) {
	ctx := context.Background()
	st := copyStore(t)
	const owner = "owner@example.com"
	src, _, _ := copyFixture(t, st, owner)

	// Copying a permit onto itself would clear its roster and then copy from the now
	// empty table — silently wiping the schedule it was meant to duplicate.
	if _, err := st.CopySchedule(ctx, owner, src, src, time.Now().UTC()); err == nil {
		t.Fatal("copying a schedule onto itself must be refused")
	}
	if rules, _ := st.ListRules(ctx, src); len(rules) != 2 {
		t.Errorf("the source lost rules to a refused self-copy: %d remain, want 2", len(rules))
	}
}

// TestMoveGuestGrants: re-pointing grants preserves their tokens (a saved link's
// identity), refuses foreign permits, and never leaves a permit with two door QRs.
func TestMoveGuestGrants(t *testing.T) {
	st := copyStore(t)
	ctx := context.Background()
	const owner = "own@example.com"
	src, dst, vehID := copyFixture(t, st, owner)

	passID, err := st.CreateGuestGrant(ctx, owner, owner, src, "Nanny", false,
		[]int64{vehID}, []GuestRecipient{{Email: "nanny@example.com", TokenHash: "hash-pass"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePrintedGrant(ctx, owner, owner, src, "hash-door", "sealed"); err != nil {
		t.Fatal(err)
	}

	// A live revert baseline on the pass and a pending printed-QR request on the
	// door grant: both permit-specific states the move must handle.
	preGC, err := st.GuestContextByTokenHash(ctx, "hash-pass")
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(6 * time.Hour)
	if _, _, err := st.CaptureOrExtendGuestBaseline(ctx, preGC.TokenID, "OLD111", end, time.Now()); err != nil {
		t.Fatal(err)
	}
	doorGrant, err := st.PrintedGrantForPermit(ctx, owner, src)
	if err != nil {
		t.Fatal(err)
	}
	reqID, _, _, err := st.CreateGuestRequest(ctx, doorGrant.GrantID, src, owner, "TRD441", "", "nonce-move")
	if err != nil {
		t.Fatal(err)
	}

	// Both grants move; the pass's token rows are untouched (same hash resolves).
	n, stranded, err := st.MoveGuestGrants(ctx, owner, src, dst)
	if err != nil || n != 2 || stranded {
		t.Fatalf("MoveGuestGrants = %d, stranded=%v, %v; want 2 grants moved, none stranded", n, stranded, err)
	}
	gc, err := st.GuestContextByTokenHash(ctx, "hash-pass")
	if err != nil || gc.Grant.PermitID != dst || gc.Grant.ID != passID {
		t.Fatalf("moved pass resolves to %+v (%v), want same grant on permit %d", gc.Grant, err, dst)
	}
	if _, err := st.PrintedGrantForPermit(ctx, owner, dst); err != nil {
		t.Fatalf("door QR did not follow: %v", err)
	}
	// The stale baseline must NOT cross: revert on the new permit would restore
	// the OLD permit's plate.
	if gc.BaselinePlate != "" {
		t.Fatalf("baseline %q survived the move; must be cleared", gc.BaselinePlate)
	}
	// The pending request follows its grant so the visitor stays approvable.
	if req, err := st.GuestRequestByID(ctx, reqID); err != nil || req.PermitID != dst || req.Status != "pending" {
		t.Fatalf("pending request after move = %+v (%v), want pending on permit %d", req, err, dst)
	}

	// A destination that already has a door QR keeps it: the source's printed
	// grant stays behind, everything else still moves.
	src2, err := st.UpsertPermit(ctx, owner, "src2-permit", "14", "Second old")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePrintedGrant(ctx, owner, owner, src2, "hash-door2", "sealed2"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGuestGrant(ctx, owner, owner, src2, "Pa", false,
		[]int64{vehID}, []GuestRecipient{{Email: "pa@example.com", TokenHash: "hash-pass2"}}); err != nil {
		t.Fatal(err)
	}
	n, stranded, err = st.MoveGuestGrants(ctx, owner, src2, dst)
	if err != nil || n != 1 || !stranded {
		t.Fatalf("second move = %d, stranded=%v, %v; want only the pass moved and the poster reported stranded", n, stranded, err)
	}
	if g, err := st.PrintedGrantForPermit(ctx, owner, src2); err != nil || g.GrantID == 0 {
		t.Fatalf("source's door QR should stay behind on collision: %+v %v", g, err)
	}

	// Foreign or unknown permits refuse wholesale.
	if _, _, err := st.MoveGuestGrants(ctx, "other@example.com", src, dst); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign owner = %v, want ErrNotFound", err)
	}
	if _, _, err := st.MoveGuestGrants(ctx, owner, src, src); err == nil {
		t.Fatal("same-permit move must refuse")
	}
}

// TestCopyScheduleEmptySourceIsNoOp: an empty source must not wipe a roster the
// household already built on the target ("nothing to copy" must mean nothing
// happened, not wreckage behind a shrug).
func TestCopyScheduleEmptySourceIsNoOp(t *testing.T) {
	st := copyStore(t)
	ctx := context.Background()
	const owner = "own@example.com"
	src, dst, vehID := copyFixture(t, st, owner)
	// Strip the fixture's source schedule so src is empty, and give DST a roster.
	if _, err := st.db.Exec(`DELETE FROM weekly_rule WHERE permit_id = ?`, src); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM override WHERE permit_id = ?`, src); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRule(ctx, dst, 0, time.Monday, vehID); err != nil {
		t.Fatal(err)
	}

	n, err := st.CopySchedule(ctx, owner, src, dst, time.Now())
	if err != nil || n != 0 {
		t.Fatalf("empty-source copy = %d, %v; want 0, nil", n, err)
	}
	rules, err := st.ListRules(ctx, dst)
	if err != nil || len(rules) != 1 {
		t.Fatalf("dst roster after empty-source copy = %v (%v); want untouched", rules, err)
	}
}
