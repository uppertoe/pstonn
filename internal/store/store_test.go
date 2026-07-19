package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestOwnerIsolation asserts that per-user reads and scoped deletes never leak
// or mutate another app user's data, the core multi-user guarantee.
func TestOwnerIsolation(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const alice, bob = "alice@example.com", "bob@example.com"

	// Vehicles: each owner sees only their own.
	aVeh, err := s.CreateVehicle(ctx, alice, "AAA111", "Alice car")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVehicle(ctx, bob, "BBB222", "Bob car"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.ListVehiclesFor(ctx, alice); len(v) != 1 || v[0].Registration != "AAA111" {
		t.Fatalf("alice vehicles = %+v, want just AAA111", v)
	}
	if v, _ := s.ListVehiclesFor(ctx, bob); len(v) != 1 || v[0].Registration != "BBB222" {
		t.Fatalf("bob vehicles = %+v, want just BBB222", v)
	}

	// Bob cannot delete Alice's vehicle by guessing its id.
	if err := s.DeleteVehicle(ctx, bob, aVeh); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.ListVehiclesFor(ctx, alice); len(v) != 1 {
		t.Fatalf("alice vehicle deleted by bob: %+v", v)
	}

	// Permits: scoped listing.
	aPermit, err := s.UpsertPermit(ctx, alice, "14576", "14", "Alice permit")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertPermit(ctx, bob, "99999", "14", "Bob permit"); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.ListPermitsFor(ctx, alice); len(p) != 1 || p[0].CouncilPermitID != "14576" {
		t.Fatalf("alice permits = %+v, want just 14576", p)
	}

	// Overrides: Bob cannot cancel an override on Alice's permit.
	end := time.Now().Add(time.Hour)
	ovr, err := s.CreateOverride(ctx, aPermit, aVeh, time.Now(), &end, alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteOverride(ctx, bob, ovr); err != nil {
		t.Fatal(err)
	}
	if o, _ := s.ListOverrides(ctx, aPermit, time.Now()); len(o) != 1 {
		t.Fatalf("alice override deleted by bob: %+v", o)
	}
	// Owner can delete their own override.
	if err := s.DeleteOverride(ctx, alice, ovr); err != nil {
		t.Fatal(err)
	}
	if o, _ := s.ListOverrides(ctx, aPermit, time.Now()); len(o) != 0 {
		t.Fatalf("override survived owner delete: %+v", o)
	}
}

// TestVehicleOwnedBy guards the IDOR fix: a vehicle_id is only bindable into a
// rule/override by its owner.
func TestVehicleOwnedBy(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const alice, bob = "alice@example.com", "bob@example.com"
	aVeh, err := s.CreateVehicle(ctx, alice, "AAA111", "Alice car")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.VehicleOwnedBy(ctx, alice, aVeh); err != nil || !ok {
		t.Fatalf("owner should own their vehicle: ok=%v err=%v", ok, err)
	}
	if ok, err := s.VehicleOwnedBy(ctx, bob, aVeh); err != nil || ok {
		t.Fatalf("bob must NOT own alice's vehicle: ok=%v err=%v", ok, err)
	}
	if ok, _ := s.VehicleOwnedBy(ctx, alice, 999999); ok {
		t.Fatal("nonexistent vehicle must not be owned")
	}
}

// TestUpsertPermitNoOwnerTakeover guards the permit-hijack fix: re-upserting an
// existing council_permit_id under a different owner must NOT reassign ownership.
func TestUpsertPermitNoOwnerTakeover(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const alice, bob = "alice@example.com", "bob@example.com"
	if _, err := s.UpsertPermit(ctx, alice, "14576", "14", "Alice permit"); err != nil {
		t.Fatal(err)
	}
	// Bob tries to claim Alice's permit id.
	if _, err := s.UpsertPermit(ctx, bob, "14576", "14", "Bob steal"); err != nil {
		t.Fatal(err)
	}
	p, err := s.PermitByCouncilID(ctx, "14576")
	if err != nil {
		t.Fatal(err)
	}
	if p.Owner != alice {
		t.Fatalf("owner was hijacked to %q, want %q", p.Owner, alice)
	}
	if p.Label != "Alice permit" {
		t.Fatalf("label overwritten to %q by non-owner upsert", p.Label)
	}
	// The real owner can still update their own permit.
	if _, err := s.UpsertPermit(ctx, alice, "14576", "14", "Alice renamed"); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.PermitByCouncilID(ctx, "14576"); p.Label != "Alice renamed" {
		t.Fatalf("owner update did not apply: %+v", p)
	}
}

// TestAccountMembers covers shared access: resolution, the one-membership rule,
// listing/counting, primary detection, and removal (by owner and by self).
func TestAccountMembers(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const primary, nanny, gran = "mum@example.com", "nanny@example.com", "gran@example.com"

	// No membership yet: everyone is their own account.
	if _, ok, _ := s.MemberAccount(ctx, nanny); ok {
		t.Fatal("nanny should not be a member of anyone yet")
	}
	if isP, _ := s.IsPrimary(ctx, primary); isP {
		t.Fatal("primary should not be flagged before adding members")
	}

	// Add two secondaries.
	if err := s.AddMember(ctx, primary, nanny); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMember(ctx, primary, gran); err != nil {
		t.Fatal(err)
	}
	if owner, ok, _ := s.MemberAccount(ctx, nanny); !ok || owner != primary {
		t.Fatalf("nanny should resolve to %s, got %q ok=%v", primary, owner, ok)
	}
	if n, _ := s.CountMembers(ctx, primary); n != 2 {
		t.Fatalf("member count = %d, want 2", n)
	}
	if isP, _ := s.IsPrimary(ctx, primary); !isP {
		t.Fatal("primary should be flagged once it has members")
	}

	// A person can belong to only one account (member_email is unique).
	if err := s.AddMember(ctx, "other@example.com", nanny); err == nil {
		t.Fatal("adding an existing member to another account should fail")
	}

	// Owner removes one; the removal is owner-scoped.
	if err := s.RemoveMember(ctx, "someone-else@example.com", gran); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountMembers(ctx, primary); n != 2 {
		t.Fatalf("wrong owner must not remove a member; count = %d, want 2", n)
	}
	if err := s.RemoveMember(ctx, primary, gran); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountMembers(ctx, primary); n != 1 {
		t.Fatalf("member count after remove = %d, want 1", n)
	}

	// Secondary leaves of their own accord.
	if err := s.RemoveMembership(ctx, nanny); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.MemberAccount(ctx, nanny); ok {
		t.Fatal("nanny should be back to their own account after leaving")
	}

	// Deleting the primary account clears any remaining members.
	if err := s.AddMember(ctx, primary, nanny); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAllForOwner(ctx, primary); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.MemberAccount(ctx, nanny); ok {
		t.Fatal("deleting the primary account should revoke shared access")
	}
}

// TestAccountEmails confirms notifications fan out to the owner plus secondaries.
func TestAccountEmails(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const owner = "mum@example.com"
	if got, _ := s.AccountEmails(ctx, owner); len(got) != 1 || got[0] != owner {
		t.Fatalf("solo account = %v, want just the owner", got)
	}
	_ = s.AddMember(ctx, owner, "nanny@example.com")
	_ = s.AddMember(ctx, owner, "gran@example.com")
	got, err := s.AccountEmails(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{owner: true, "nanny@example.com": true, "gran@example.com": true}
	if len(got) != 3 {
		t.Fatalf("got %v, want 3 recipients", got)
	}
	for _, e := range got {
		if !want[e] {
			t.Fatalf("unexpected recipient %q in %v", e, got)
		}
	}
}

// TestAddMemberCapped guards the atomic cap: adds succeed under the limit and
// return ErrMemberLimit once full.
func TestAddMemberCapped(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const owner = "mum@example.com"
	if err := s.AddMemberCapped(ctx, owner, "a@example.com", 2); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMemberCapped(ctx, owner, "b@example.com", 2); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMemberCapped(ctx, owner, "c@example.com", 2); !errors.Is(err, ErrMemberLimit) {
		t.Fatalf("third add should hit the limit, got %v", err)
	}
	if n, _ := s.CountMembers(ctx, owner); n != 2 {
		t.Fatalf("member count = %d, want 2", n)
	}
	// A different account is unaffected by the first account's cap.
	if err := s.AddMemberCapped(ctx, "other@example.com", "d@example.com", 2); err != nil {
		t.Fatalf("another account should still be able to add: %v", err)
	}
}

// TestHasOwnData guards the "can't invite an existing user" rule: a fresh email
// has no data, but one with a vehicle (or permit, or council session) does.
func TestHasOwnData(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if has, err := s.HasOwnData(ctx, "fresh@example.com"); err != nil || has {
		t.Fatalf("fresh email should have no data: has=%v err=%v", has, err)
	}
	if _, err := s.CreateVehicle(ctx, "active@example.com", "AAA111", "car"); err != nil {
		t.Fatal(err)
	}
	if has, err := s.HasOwnData(ctx, "active@example.com"); err != nil || !has {
		t.Fatalf("email with a vehicle should have data: has=%v err=%v", has, err)
	}
}

// TestSaveCouncilSessionStampsLinkedAt confirms an interactive save sets the
// re-authorise clock, and that ListCouncilSessions surfaces it.
func TestSaveCouncilSessionStampsLinkedAt(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.SaveCouncilSession(ctx, CouncilSession{Owner: "u@example.com", Cookie: "sealed"}); err != nil {
		t.Fatal(err)
	}
	cs, err := s.GetCouncilSession(ctx, "u@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cs.LinkedAt.IsZero() {
		t.Fatal("linked_at not stamped on save")
	}
	// A token renewal must NOT move the re-authorise clock.
	if err := s.UpdateCouncilToken(ctx, "u@example.com", "sealed2", "at", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	cs2, _ := s.GetCouncilSession(ctx, "u@example.com")
	if !cs2.LinkedAt.Equal(cs.LinkedAt) {
		t.Fatalf("linked_at moved on token renew: %v -> %v", cs.LinkedAt, cs2.LinkedAt)
	}
	all, err := s.ListCouncilSessions(ctx)
	if err != nil || len(all) != 1 || all[0].Owner != "u@example.com" {
		t.Fatalf("ListCouncilSessions = %+v, err=%v", all, err)
	}
}

// TestReminderAndConfirm covers the reminder token round-trip: mark a reminder,
// then a confirm consumes the token, resets the re-authorise clock forward, and
// clears the cycle. Uses a backdated linked_at so the extension is observable.
func TestReminderAndConfirm(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const owner = "u@example.com"
	if err := s.SaveCouncilSession(ctx, CouncilSession{Owner: owner, Cookie: "c"}); err != nil {
		t.Fatal(err)
	}
	// Backdate the link so a confirm visibly moves linked_at forward.
	old := time.Now().Add(-80 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := s.db.ExecContext(ctx, `UPDATE council_session SET linked_at = ? WHERE owner = ?`, old, owner); err != nil {
		t.Fatal(err)
	}

	if err := s.MarkReminderSent(ctx, owner, "tok-123"); err != nil {
		t.Fatal(err)
	}
	cs, _ := s.GetCouncilSession(ctx, owner)
	if cs.ReminderSent.IsZero() || cs.ConfirmToken != "tok-123" {
		t.Fatalf("reminder not marked: %+v", cs)
	}

	// A bad token confirms nothing.
	if _, err := s.ConfirmSession(ctx, "wrong"); err != ErrNotFound {
		t.Fatalf("ConfirmSession(wrong) err = %v, want ErrNotFound", err)
	}

	got, err := s.ConfirmSession(ctx, "tok-123")
	if err != nil || got != owner {
		t.Fatalf("ConfirmSession = %q, %v", got, err)
	}
	cs2, _ := s.GetCouncilSession(ctx, owner)
	if !cs2.LinkedAt.After(cs.LinkedAt) {
		t.Fatalf("linked_at not extended: %v -> %v", cs.LinkedAt, cs2.LinkedAt)
	}
	if !cs2.ReminderSent.IsZero() || cs2.ConfirmToken != "" {
		t.Fatalf("confirm did not clear the cycle: %+v", cs2)
	}
	// Token is single-use.
	if _, err := s.ConfirmSession(ctx, "tok-123"); err != ErrNotFound {
		t.Fatalf("token reuse should fail: %v", err)
	}
}

// TestConsent records acceptances and returns the latest (for the terms gate).
func TestConsent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.LatestConsent(ctx, "u@example.com"); err != ErrNotFound {
		t.Fatalf("no consent yet = %v, want ErrNotFound", err)
	}
	if err := s.RecordConsent(ctx, "u@example.com", "2026-01-01", "hashA"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordConsent(ctx, "u@example.com", "2026-07-18", "hashB"); err != nil {
		t.Fatal(err)
	}
	c, err := s.LatestConsent(ctx, "u@example.com")
	if err != nil || c.Version != "2026-07-18" || c.Hash != "hashB" {
		t.Fatalf("LatestConsent = %+v, %v", c, err)
	}
}

// TestNotifyPrefDefaults confirms a never-set user gets email-on defaults, and
// that saved prefs round-trip.
func TestNotifyPrefDefaults(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	p, err := s.GetNotifyPref(ctx, "u@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !p.EmailEnabled || p.NtfyEnabled || p.FailuresOnly {
		t.Fatalf("bad defaults: %+v", p)
	}
	p.NtfyEnabled, p.NtfyTopic, p.FailuresOnly, p.EmailEnabled = true, "pstonn-abc", true, false
	if err := s.SetNotifyPref(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNotifyPref(ctx, "u@example.com")
	if got.EmailEnabled || !got.NtfyEnabled || got.NtfyTopic != "pstonn-abc" || !got.FailuresOnly {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// TestLastApply returns the newest apply row (for notification de-dup).
func TestLastApply(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	pid, _ := s.UpsertPermit(ctx, "u@example.com", "p1", "14", "P")
	if _, err := s.LastApply(ctx, pid); err != ErrNotFound {
		t.Fatalf("empty LastApply = %v, want ErrNotFound", err)
	}
	_ = s.RecordApply(ctx, pid, "AAA111", "roster", "success", "")
	_ = s.RecordApply(ctx, pid, "BBB222", "override", "error", "boom")
	last, err := s.LastApply(ctx, pid)
	if err != nil || last.Registration != "BBB222" || last.Status != "error" || last.Detail != "boom" {
		t.Fatalf("LastApply = %+v, %v", last, err)
	}
}

// TestOwnerHasSchedule reflects whether the owner has any rule/override.
func TestOwnerHasSchedule(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const owner = "u@example.com"
	if has, err := s.OwnerHasSchedule(ctx, owner); err != nil || has {
		t.Fatalf("empty owner has schedule = %v, %v", has, err)
	}
	veh, _ := s.CreateVehicle(ctx, owner, "REG1", "car")
	pid, _ := s.UpsertPermit(ctx, owner, "p1", "14", "P")
	if err := s.SetRule(ctx, pid, time.Monday, veh); err != nil {
		t.Fatal(err)
	}
	if has, err := s.OwnerHasSchedule(ctx, owner); err != nil || !has {
		t.Fatalf("owner with a rule has schedule = %v, %v", has, err)
	}
}

// TestDeleteAllForOwner wipes one user's world without touching another's.
func TestDeleteAllForOwner(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const alice, bob = "alice@example.com", "bob@example.com"

	for _, owner := range []string{alice, bob} {
		if err := s.SaveCouncilSession(ctx, CouncilSession{Owner: owner, Cookie: "c"}); err != nil {
			t.Fatal(err)
		}
		veh, err := s.CreateVehicle(ctx, owner, "REG"+owner[:1], "car")
		if err != nil {
			t.Fatal(err)
		}
		pid, err := s.UpsertPermit(ctx, owner, "perm-"+owner, "14", "P")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetRule(ctx, pid, time.Monday, veh); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateOverride(ctx, pid, veh, time.Now(), nil, owner); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordApply(ctx, pid, "REG", "roster", "success", ""); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.DeleteAllForOwner(ctx, alice); err != nil {
		t.Fatal(err)
	}

	// Alice is gone everywhere.
	if _, err := s.GetCouncilSession(ctx, alice); err != ErrNotFound {
		t.Fatalf("alice session survived: %v", err)
	}
	if v, _ := s.ListVehiclesFor(ctx, alice); len(v) != 0 {
		t.Fatalf("alice vehicles survived: %+v", v)
	}
	if p, _ := s.ListPermitsFor(ctx, alice); len(p) != 0 {
		t.Fatalf("alice permits survived: %+v", p)
	}
	if l, _ := s.ListApplyLogFor(ctx, alice, 10); len(l) != 0 {
		t.Fatalf("alice apply-log survived: %+v", l)
	}
	// Bob is untouched.
	if _, err := s.GetCouncilSession(ctx, bob); err != nil {
		t.Fatalf("bob session removed: %v", err)
	}
	if p, _ := s.ListPermitsFor(ctx, bob); len(p) != 1 {
		t.Fatalf("bob permits = %+v, want 1", p)
	}
	if l, _ := s.ListApplyLogFor(ctx, bob, 10); len(l) != 1 {
		t.Fatalf("bob apply-log = %+v, want 1", l)
	}
}

func TestDeletePermit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const alice, bob = "alice@example.com", "bob@example.com"

	veh, err := s.CreateVehicle(ctx, alice, "AAA111", "car")
	if err != nil {
		t.Fatal(err)
	}
	pid, err := s.UpsertPermit(ctx, alice, "14576", "14", "Alice permit")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRule(ctx, pid, time.Monday, veh); err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(time.Hour)
	if _, err := s.CreateOverride(ctx, pid, veh, time.Now(), &end, alice); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordApply(ctx, pid, "AAA111", "roster", "success", ""); err != nil {
		t.Fatal(err)
	}

	// A different account cannot delete this permit, and it must survive intact.
	if err := s.DeletePermit(ctx, pid, bob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob deleting alice's permit = %v, want ErrNotFound", err)
	}
	if ps, _ := s.ListPermitsFor(ctx, alice); len(ps) != 1 {
		t.Fatalf("permit should survive a foreign delete, got %d", len(ps))
	}

	// The owner removes it: permit gone, schedule cascaded, history cleared.
	if err := s.DeletePermit(ctx, pid, alice); err != nil {
		t.Fatalf("alice delete: %v", err)
	}
	if ps, _ := s.ListPermitsFor(ctx, alice); len(ps) != 0 {
		t.Fatalf("permit not removed, got %d", len(ps))
	}
	if rs, _ := s.ListRules(ctx, pid); len(rs) != 0 {
		t.Errorf("weekly rules not cascaded, got %d", len(rs))
	}
	if ovs, _ := s.ListOverrides(ctx, pid, time.Now()); len(ovs) != 0 {
		t.Errorf("overrides not cascaded, got %d", len(ovs))
	}

	// Deleting again is a clean not-found; the vehicle is untouched.
	if err := s.DeletePermit(ctx, pid, alice); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete = %v, want ErrNotFound", err)
	}
	if vs, _ := s.ListVehiclesFor(ctx, alice); len(vs) != 1 {
		t.Errorf("vehicle should survive permit removal, got %d", len(vs))
	}
}

func TestGuestPasses(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const alice, bob = "alice@example.com", "bob@example.com"

	aV1, _ := s.CreateVehicle(ctx, alice, "AAA111", "Mum")
	aV2, _ := s.CreateVehicle(ctx, alice, "AAA222", "Dad")
	bV, _ := s.CreateVehicle(ctx, bob, "BBB111", "Bob")
	aPermit, _ := s.UpsertPermit(ctx, alice, "P1", "14", "Alice permit")
	bPermit, _ := s.UpsertPermit(ctx, bob, "P2", "14", "Bob permit")

	// A foreign permit is rejected.
	if _, err := s.CreateGuestGrant(ctx, alice, bPermit, "x", false, []int64{aV1}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign permit = %v, want ErrNotFound", err)
	}
	// A foreign car is rejected.
	if _, err := s.CreateGuestGrant(ctx, alice, aPermit, "x", false, []int64{bV}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign vehicle = %v, want ErrNotFound", err)
	}

	recips := []GuestRecipient{{Email: "dad@example.com", TokenHash: "hashD"}, {Email: "mum@example.com", TokenHash: "hashM"}}
	grantID, err := s.CreateGuestGrant(ctx, alice, aPermit, "Friday", true, []int64{aV1, aV2}, recips)
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}

	// A live token resolves to the grant, recipient, and allowed cars.
	gc, err := s.GuestContextByTokenHash(ctx, "hashD")
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if gc.Grant.Owner != alice || gc.Grant.PermitID != aPermit || gc.Recipient != "dad@example.com" ||
		!gc.Grant.AllowOvernight || len(gc.Vehicles) != 2 {
		t.Fatalf("unexpected context: %+v", gc)
	}
	// An unknown token is not found.
	if _, err := s.GuestContextByTokenHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown token = %v, want ErrNotFound", err)
	}

	// The kill-switch disables every link; re-enabling restores them.
	if err := s.SetGuestsEnabled(ctx, alice, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GuestContextByTokenHash(ctx, "hashD"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("kill-switch: token still resolves")
	}
	if on, _ := s.GuestsEnabled(ctx, alice); on {
		t.Fatal("GuestsEnabled should be false")
	}
	if err := s.SetGuestsEnabled(ctx, alice, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GuestContextByTokenHash(ctx, "hashD"); err != nil {
		t.Fatalf("re-enabled token: %v", err)
	}

	// Find dad's token id via the management listing.
	details, err := s.ListGuestGrants(ctx, alice)
	if err != nil || len(details) != 1 || len(details[0].Tokens) != 2 || len(details[0].Vehicles) != 2 {
		t.Fatalf("list grants: %+v err=%v", details, err)
	}
	var dadTok int64
	for _, tk := range details[0].Tokens {
		if tk.RecipientEmail == "dad@example.com" {
			dadTok = tk.ID
		}
	}

	// A foreign owner cannot revoke; the real owner can.
	if err := s.RevokeGuestToken(ctx, bob, dadTok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign revoke = %v, want ErrNotFound", err)
	}
	if err := s.RevokeGuestToken(ctx, alice, dadTok); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.GuestContextByTokenHash(ctx, "hashD"); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked token still resolves")
	}
	// Mum's token still works.
	if _, err := s.GuestContextByTokenHash(ctx, "hashM"); err != nil {
		t.Fatalf("mum's token: %v", err)
	}

	// Deleting the grant (owner-scoped) removes it and its tokens.
	if err := s.DeleteGuestGrant(ctx, bob, grantID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign delete = %v, want ErrNotFound", err)
	}
	if err := s.DeleteGuestGrant(ctx, alice, grantID); err != nil {
		t.Fatalf("delete grant: %v", err)
	}
	if _, err := s.GuestContextByTokenHash(ctx, "hashM"); !errors.Is(err, ErrNotFound) {
		t.Fatal("token survives grant deletion")
	}
	if ds, _ := s.ListGuestGrants(ctx, alice); len(ds) != 0 {
		t.Fatalf("grant not deleted: %+v", ds)
	}
}

func TestGuestGrantEdit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const alice, bob = "alice@example.com", "bob@example.com"

	v1, _ := s.CreateVehicle(ctx, alice, "AAA111", "Mum")
	v2, _ := s.CreateVehicle(ctx, alice, "AAA222", "Dad")
	bV, _ := s.CreateVehicle(ctx, bob, "BBB111", "Bob")
	p, _ := s.UpsertPermit(ctx, alice, "P1", "14", "Alice permit")

	gid, err := s.CreateGuestGrant(ctx, alice, p, "Friday", false, []int64{v1}, []GuestRecipient{{Email: "mum@example.com", TokenHash: "h1"}})
	if err != nil {
		t.Fatal(err)
	}

	// Update: relabel, allow overnight, swap the car set to {v1, v2}.
	if err := s.UpdateGuestGrant(ctx, alice, gid, "Weekend", true, []int64{v1, v2}); err != nil {
		t.Fatalf("update: %v", err)
	}
	// A foreign owner cannot update; a foreign car is rejected.
	if err := s.UpdateGuestGrant(ctx, bob, gid, "x", false, []int64{v1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign update = %v, want ErrNotFound", err)
	}
	if err := s.UpdateGuestGrant(ctx, alice, gid, "x", false, []int64{bV}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign car update = %v, want ErrNotFound", err)
	}

	details, _ := s.ListGuestGrants(ctx, alice)
	if len(details) != 1 || details[0].Grant.Label != "Weekend" || !details[0].Grant.AllowOvernight || len(details[0].Vehicles) != 2 {
		t.Fatalf("after update: %+v", details[0].Grant)
	}

	// AddGuestTokens: a new recipient is added; an existing live one is skipped.
	added, err := s.AddGuestTokens(ctx, alice, gid, []GuestRecipient{
		{Email: "dad@example.com", TokenHash: "h2"}, {Email: "mum@example.com", TokenHash: "hdup"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != "dad@example.com" {
		t.Fatalf("added = %v, want just dad", added)
	}
	if _, err := s.GuestContextByTokenHash(ctx, "h2"); err != nil {
		t.Fatalf("new token h2: %v", err)
	}
	if _, err := s.GuestContextByTokenHash(ctx, "hdup"); !errors.Is(err, ErrNotFound) {
		t.Fatal("duplicate recipient should not have been added")
	}
	// Foreign owner cannot add tokens.
	if _, err := s.AddGuestTokens(ctx, bob, gid, []GuestRecipient{{Email: "x@example.com", TokenHash: "h9"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign add = %v, want ErrNotFound", err)
	}
}

func TestPlateOverride(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const owner = "u@example.com"
	p, _ := s.UpsertPermit(ctx, owner, "P1", "14", "Permit")
	v, _ := s.CreateVehicle(ctx, owner, "AAA111", "Saved car")
	now := time.Now()
	end := now.Add(2 * time.Hour)

	// An ad-hoc plate override: no vehicle, literal registration.
	if _, err := s.CreatePlateOverride(ctx, p, "VISITOR1", now, &end, owner); err != nil {
		t.Fatalf("plate override: %v", err)
	}
	// A saved-vehicle override for comparison.
	if _, err := s.CreateOverride(ctx, p, v, now, &end, owner); err != nil {
		t.Fatalf("vehicle override: %v", err)
	}

	ovs, err := s.ListOverrides(ctx, p, now)
	if err != nil || len(ovs) != 2 {
		t.Fatalf("list: %v (%d)", err, len(ovs))
	}
	var gotPlate, gotVehicle bool
	for _, o := range ovs {
		if o.Registration == "VISITOR1" && o.VehicleID == 0 {
			gotPlate = true
		}
		if o.VehicleID == v && o.Registration == "" {
			gotVehicle = true
		}
	}
	if !gotPlate {
		t.Error("ad-hoc plate override not read back with registration + null vehicle")
	}
	if !gotVehicle {
		t.Error("saved-vehicle override should have a vehicle id and empty registration")
	}
}

func TestQRGrant(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const owner, bob = "u@example.com", "bob@example.com"
	p, _ := s.UpsertPermit(ctx, owner, "P1", "14", "Permit")
	bp, _ := s.UpsertPermit(ctx, bob, "P2", "14", "Bob permit")

	// A foreign permit is rejected.
	if _, err := s.CreateQRGrant(ctx, owner, bp, "x", time.Hour); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign permit = %v, want ErrNotFound", err)
	}

	// A valid QR grant resolves with plate entry allowed and no cars.
	if _, err := s.CreateQRGrant(ctx, owner, p, "qrhash", time.Hour); err != nil {
		t.Fatal(err)
	}
	gc, err := s.GuestContextByTokenHash(ctx, "qrhash")
	if err != nil {
		t.Fatalf("resolve QR token: %v", err)
	}
	if !gc.Grant.AllowPlate || len(gc.Vehicles) != 0 || gc.Grant.Owner != owner {
		t.Fatalf("QR context: %+v", gc)
	}

	// It is hidden from the management list.
	if ds, _ := s.ListGuestGrants(ctx, owner); len(ds) != 0 {
		t.Fatalf("QR grant should be hidden from the pass list, got %d", len(ds))
	}

	// An expired token is treated as not-found.
	if _, err := s.CreateQRGrant(ctx, owner, p, "expiredhash", -time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GuestContextByTokenHash(ctx, "expiredhash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired QR token = %v, want ErrNotFound", err)
	}
}

func TestPrintedRequestFlow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const owner, bob = "u@example.com", "bob@example.com"
	p, _ := s.UpsertPermit(ctx, owner, "P1", "14", "Permit")
	bp, _ := s.UpsertPermit(ctx, bob, "P2", "14", "Bob permit")

	// A foreign permit can't back a printed grant.
	if _, err := s.CreatePrintedGrant(ctx, owner, bp, "x", "xsealed"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign permit = %v, want ErrNotFound", err)
	}

	// The printed grant is request-only, allows free plate entry, and stays hidden
	// from the management list (like the on-screen QR).
	grantID, err := s.CreatePrintedGrant(ctx, owner, p, "printhash", "sealed1")
	if err != nil {
		t.Fatal(err)
	}
	gc, err := s.GuestContextByTokenHash(ctx, "printhash")
	if err != nil {
		t.Fatalf("resolve printed token: %v", err)
	}
	if !gc.Grant.AllowPlate || !gc.Grant.RequestOnly || gc.Grant.Owner != owner {
		t.Fatalf("printed context: %+v", gc)
	}
	if ds, _ := s.ListGuestGrants(ctx, owner); len(ds) != 0 {
		t.Fatalf("printed grant should be hidden from the pass list, got %d", len(ds))
	}

	// Showing a printed QR again replaces the prior grant for that permit (and, by
	// cascade, any requests against it), so the old token stops resolving.
	grantID, err = s.CreatePrintedGrant(ctx, owner, p, "printhash2", "sealed2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GuestContextByTokenHash(ctx, "printhash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replaced printed token still resolves = %v, want ErrNotFound", err)
	}

	// A scan records a pending request the visitor can poll only with its nonce.
	reqID, err := s.CreateGuestRequest(ctx, grantID, p, owner, "TRADIE1", "secretnonce")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GuestRequestForPoll(ctx, reqID, "wrongnonce"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("poll with wrong nonce = %v, want ErrNotFound", err)
	}
	if r, err := s.GuestRequestForPoll(ctx, reqID, "secretnonce"); err != nil || r.Status != "pending" {
		t.Fatalf("poll with nonce = %+v, %v", r, err)
	}

	// It appears in the owner's approvals queue, but not another owner's.
	if reqs, _ := s.ListPendingRequests(ctx, owner); len(reqs) != 1 || reqs[0].Plate != "TRADIE1" {
		t.Fatalf("owner queue = %+v", reqs)
	}
	if reqs, _ := s.ListPendingRequests(ctx, bob); len(reqs) != 0 {
		t.Fatalf("foreign owner should see no requests, got %d", len(reqs))
	}

	// Another owner can't decide it; the real owner can approve once.
	if _, err := s.DecideGuestRequest(ctx, bob, reqID, true, "2026-07-21T00:00:00Z"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign decide = %v, want ErrNotFound", err)
	}
	dec, err := s.DecideGuestRequest(ctx, owner, reqID, true, "2026-07-21T00:00:00Z")
	if err != nil || dec.Status != "approved" || dec.Until != "2026-07-21T00:00:00Z" {
		t.Fatalf("approve = %+v, %v", dec, err)
	}
	// Deciding again is a no-op (no longer pending) and drops out of the queue.
	if _, err := s.DecideGuestRequest(ctx, owner, reqID, true, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-decide = %v, want ErrNotFound", err)
	}
	if reqs, _ := s.ListPendingRequests(ctx, owner); len(reqs) != 0 {
		t.Fatalf("decided request should leave the queue, got %d", len(reqs))
	}
}

func TestPrintedGrantPersistence(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const owner, bob = "u@example.com", "bob@example.com"
	p, _ := s.UpsertPermit(ctx, owner, "P1", "14", "1st Visitor Permit")
	s.UpsertPermit(ctx, bob, "P2", "14", "Bob permit")

	// No door QR yet.
	if _, err := s.PrintedGrantForPermit(ctx, owner, p); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no grant yet = %v, want ErrNotFound", err)
	}
	if ds, _ := s.ListPrintedGrants(ctx, owner); len(ds) != 0 {
		t.Fatalf("empty list expected, got %d", len(ds))
	}

	// Mint one; it's findable by permit and by id, carries the sealed token + label.
	grantID, err := s.CreatePrintedGrant(ctx, owner, p, "hashA", "sealedA")
	if err != nil {
		t.Fatal(err)
	}
	byPermit, err := s.PrintedGrantForPermit(ctx, owner, p)
	if err != nil || byPermit.GrantID != grantID || byPermit.TokenSealed != "sealedA" || byPermit.PermitLabel != "1st Visitor Permit" {
		t.Fatalf("byPermit = %+v, %v", byPermit, err)
	}
	byID, err := s.PrintedGrantByID(ctx, owner, grantID)
	if err != nil || byID.TokenSealed != "sealedA" {
		t.Fatalf("byID = %+v, %v", byID, err)
	}

	// Another owner can neither see nor open it.
	if _, err := s.PrintedGrantByID(ctx, bob, grantID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign byID = %v, want ErrNotFound", err)
	}
	if ds, _ := s.ListPrintedGrants(ctx, bob); len(ds) != 0 {
		t.Fatalf("foreign list should be empty, got %d", len(ds))
	}

	// Replace rotates the sealed token but keeps one grant per permit.
	newID, err := s.CreatePrintedGrant(ctx, owner, p, "hashB", "sealedB")
	if err != nil {
		t.Fatal(err)
	}
	if newID == grantID {
		t.Fatal("replace should mint a new grant id")
	}
	if _, err := s.PrintedGrantByID(ctx, owner, grantID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old grant should be gone = %v", err)
	}
	again, _ := s.PrintedGrantForPermit(ctx, owner, p)
	if again.TokenSealed != "sealedB" {
		t.Fatalf("after replace sealed = %q, want sealedB", again.TokenSealed)
	}
	if ds, _ := s.ListPrintedGrants(ctx, owner); len(ds) != 1 {
		t.Fatalf("still one door QR per permit, got %d", len(ds))
	}

	// Revoke retires it; a second revoke is ErrNotFound.
	if err := s.RevokePrintedGrant(ctx, owner, newID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := s.RevokePrintedGrant(ctx, owner, newID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double revoke = %v, want ErrNotFound", err)
	}
	if _, err := s.PrintedGrantForPermit(ctx, owner, p); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after revoke = %v, want ErrNotFound", err)
	}
}
