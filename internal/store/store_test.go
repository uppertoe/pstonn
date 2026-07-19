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
