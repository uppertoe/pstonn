package store

import (
	"context"
	"errors"
	"testing"
)

// TestPickerGrantLifecycle: the household's quick picker is a guest grant it
// keeps for itself. One per account, its own regos, a sealed token that can be
// re-shown and rotated in place, hidden from the pass list, and gone with the
// ordinary grant delete.
func TestPickerGrantLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	const owner = "a@b.com"
	pid, err := st.UpsertPermit(ctx, owner, "P1", "14", "Home")
	if err != nil {
		t.Fatal(err)
	}
	nana, err := st.CreateVehicle(ctx, owner, "ABC123", "Nana", "")
	if err != nil {
		t.Fatal(err)
	}
	baba, err := st.CreateVehicle(ctx, owner, "XYZ789", "Baba", "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := st.CreateVehicle(ctx, "z@b.com", "OTH111", "Theirs", "")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := st.PickerGrant(ctx, owner); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fresh account: %v, want ErrNotFound", err)
	}
	// Someone else's rego, no regos at all, someone else's permit: refused.
	if _, err := st.CreatePickerGrant(ctx, owner, owner, pid, true, []int64{nana, other}, "h-bad", "s-bad"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign rego: %v", err)
	}
	if _, err := st.CreatePickerGrant(ctx, owner, owner, pid, true, nil, "h-none", "s-none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no regos: %v", err)
	}
	if _, err := st.CreatePickerGrant(ctx, "z@b.com", "z@b.com", pid, true, []int64{other}, "h-perm", "s-perm"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign permit: %v", err)
	}
	if _, err := st.PickerGrant(ctx, owner); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused create left a picker behind: %v", err)
	}

	gid, err := st.CreatePickerGrant(ctx, owner, owner, pid, true, []int64{nana, baba}, "hash-1", "sealed-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePickerGrant(ctx, owner, owner, pid, false, []int64{nana}, "hash-2", "sealed-2"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second picker: %v, want ErrDuplicate", err)
	}
	pg, err := st.PickerGrant(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if pg.GrantID != gid || pg.PermitID != pid || !pg.AllowOvernight || pg.TokenSealed != "sealed-1" || len(pg.Vehicles) != 2 {
		t.Fatalf("picker = %+v", pg)
	}
	// Resolves as a picker on the public path, with its regos.
	gc, err := st.GuestContextByTokenHash(ctx, "hash-1")
	if err != nil || !gc.Grant.Picker || gc.Grant.AllowPlate || gc.Grant.RequestOnly || len(gc.Vehicles) != 2 || gc.TokenID != pg.TokenID {
		t.Fatalf("context = %+v %v", gc, err)
	}
	// Not an emailed pass: absent from the list and the pass count.
	if list, err := st.ListGuestGrants(ctx, owner); err != nil || len(list) != 0 {
		t.Fatalf("pass list = %+v %v", list, err)
	}
	if passes, printed, shown, err := st.GuestGrantKinds(ctx, owner); err != nil || passes != 0 || printed != 0 || shown != 0 {
		t.Fatalf("kinds = %d %d %d %v", passes, printed, shown, err)
	}

	// Rotating rebinds the SAME token row: the old link dies, the id survives.
	if err := st.RotatePickerToken(ctx, owner, "hash-3", "sealed-3"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GuestContextByTokenHash(ctx, "hash-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old link still resolves: %v", err)
	}
	gc2, err := st.GuestContextByTokenHash(ctx, "hash-3")
	if err != nil || gc2.TokenID != gc.TokenID {
		t.Fatalf("rotated context = %+v %v (want token id %d)", gc2, err, gc.TokenID)
	}
	if pg, _ = st.PickerGrant(ctx, owner); pg.TokenSealed != "sealed-3" {
		t.Fatalf("sealed token after rotate = %q", pg.TokenSealed)
	}
	if err := st.RotatePickerToken(ctx, "z@b.com", "hash-4", "sealed-4"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotate without a picker: %v", err)
	}

	// Changing the regos goes through the ordinary grant update.
	if _, err := st.UpdateGuestGrant(ctx, owner, gid, "Quick picker", false, []int64{baba}); err != nil {
		t.Fatal(err)
	}
	if pg, _ = st.PickerGrant(ctx, owner); pg.AllowOvernight || len(pg.Vehicles) != 1 || pg.Vehicles[0].ID != baba {
		t.Fatalf("after update = %+v", pg)
	}

	// And the ordinary delete removes it, so a new one can be made.
	if err := st.DeleteGuestGrant(ctx, owner, gid); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PickerGrant(ctx, owner); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if _, err := st.CreatePickerGrant(ctx, owner, owner, pid, false, []int64{nana}, "hash-5", "sealed-5"); err != nil {
		t.Fatalf("recreate after delete: %v", err)
	}
}
