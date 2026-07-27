package store

import (
	"context"
	"database/sql"
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
// TestVehicleColorStable: a plate keeps its colour when other plates are added,
// even one whose label sorts ahead of it (the reported "colours reshuffle" bug).
func TestVehicleColorStable(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	owner := "v@example.com"
	if _, err := s.CreateVehicle(ctx, owner, "BBB111", "Bravo"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVehicle(ctx, owner, "CCC111", "Charlie"); err != nil {
		t.Fatal(err)
	}
	colorOf := func() map[string]string {
		m := map[string]string{}
		vs, err := s.ListVehiclesFor(ctx, owner)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vs {
			if v.Color == "" {
				t.Fatalf("vehicle %s has no colour", v.Registration)
			}
			m[v.Registration] = v.Color
		}
		return m
	}
	before := colorOf()
	if before["BBB111"] == before["CCC111"] {
		t.Fatal("two vehicles were given the same colour")
	}
	// Add a plate whose label sorts FIRST — the old position-based scheme would
	// have shifted Bravo/Charlie onto new colours.
	if _, err := s.CreateVehicle(ctx, owner, "AAA111", "Alpha"); err != nil {
		t.Fatal(err)
	}
	after := colorOf()
	if after["BBB111"] != before["BBB111"] || after["CCC111"] != before["CCC111"] {
		t.Fatalf("colours reshuffled on add: before=%v after=%v", before, after)
	}
	if after["AAA111"] == after["BBB111"] || after["AAA111"] == after["CCC111"] {
		t.Fatalf("new plate collided with an existing colour: %v", after)
	}
}

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
	// Bob tries to claim Alice's permit id: no takeover, and no silent success —
	// returning Alice's row id as if it were Bob's would hand a foreign id to
	// any caller that then writes through it.
	if _, err := s.UpsertPermit(ctx, bob, "14576", "14", "Bob steal"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("foreign upsert = %v, want ErrDuplicate", err)
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
	// Re-adding the permit no longer clobbers the label, so a name the owner chose
	// survives a re-add through the picker.
	if _, err := s.UpsertPermit(ctx, alice, "14576", "14", "ignored on re-add"); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.PermitByCouncilID(ctx, "14576"); p.Label != "Alice permit" {
		t.Fatalf("re-add should keep the existing label, got %q", p.Label)
	}
	// Renaming goes through SetPermitLabel, and only the owner may do it.
	if err := s.SetPermitLabel(ctx, bob, p.ID, "Bob rename"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("non-owner rename = %v, want ErrNotFound", err)
	}
	if err := s.SetPermitLabel(ctx, alice, p.ID, "Nanny"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.PermitByCouncilID(ctx, "14576"); got.Label != "Nanny" {
		t.Fatalf("SetPermitLabel did not apply: %+v", got)
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

// TestCouncilPasswordRoundTrip covers the opt-in saved-password lifecycle: it
// persists across a save, a token renewal preserves it, a re-save without it
// clears it, and ClearCouncilPassword drops it while keeping the session.
func TestCouncilPasswordRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	owner := "p@example.com"

	// Saved with a sealed password.
	if err := s.SaveCouncilSession(ctx, CouncilSession{Owner: owner, Cookie: "c", Password: "sealed-pw"}); err != nil {
		t.Fatal(err)
	}
	if cs, _ := s.GetCouncilSession(ctx, owner); cs.Password != "sealed-pw" {
		t.Fatalf("password not persisted, got %q", cs.Password)
	}
	// A token renewal must preserve the saved password.
	if err := s.UpdateCouncilToken(ctx, owner, "c2", "at", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if cs, _ := s.GetCouncilSession(ctx, owner); cs.Password != "sealed-pw" {
		t.Fatalf("token renew wiped saved password, got %q", cs.Password)
	}
	// ClearCouncilPassword drops it but keeps the session.
	if err := s.ClearCouncilPassword(ctx, owner); err != nil {
		t.Fatal(err)
	}
	cs, err := s.GetCouncilSession(ctx, owner)
	if err != nil {
		t.Fatalf("session should survive clearing password: %v", err)
	}
	if cs.Password != "" {
		t.Fatalf("password not cleared, got %q", cs.Password)
	}
	// Re-linking without opting in leaves it empty.
	if err := s.SaveCouncilSession(ctx, CouncilSession{Owner: owner, Cookie: "c3"}); err != nil {
		t.Fatal(err)
	}
	if cs, _ := s.GetCouncilSession(ctx, owner); cs.Password != "" {
		t.Fatalf("re-save without password should clear it, got %q", cs.Password)
	}
}

// TestCopySchedule covers cloning a renewed permit's roster + live overrides.
func TestCopySchedule(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	owner := "c@example.com"
	veh, err := s.CreateVehicle(ctx, owner, "AAA111", "Car")
	if err != nil {
		t.Fatal(err)
	}
	src, err := s.UpsertPermit(ctx, owner, "old-1", "14", "Old")
	if err != nil {
		t.Fatal(err)
	}
	dst, err := s.UpsertPermit(ctx, owner, "new-1", "14", "New")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRule(ctx, src, time.Monday, veh); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRule(ctx, src, time.Friday, veh); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(48 * time.Hour)
	if _, err := s.CreateOverride(ctx, src, veh, time.Now(), &future, owner); err != nil {
		t.Fatal(err)
	}
	// An already-ended override must NOT be carried over.
	pastStart := time.Now().Add(-72 * time.Hour)
	pastEnd := time.Now().Add(-48 * time.Hour)
	if _, err := s.CreateOverride(ctx, src, veh, pastStart, &pastEnd, owner); err != nil {
		t.Fatal(err)
	}

	n, err := s.CopySchedule(ctx, owner, src, dst, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 { // 2 rules + 1 live override
		t.Fatalf("copied count = %d, want 3", n)
	}
	rules, _ := s.ListRules(ctx, dst)
	if len(rules) != 2 {
		t.Fatalf("dst rules = %d, want 2", len(rules))
	}
	ovs, _ := s.ListOverrides(ctx, dst, time.Now())
	if len(ovs) != 1 {
		t.Fatalf("dst live overrides = %d, want 1", len(ovs))
	}
	// Idempotent replace: copying again yields the SAME result, not duplicates.
	n2, err := s.CopySchedule(ctx, owner, src, dst, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 3 {
		t.Fatalf("second copy count = %d, want 3 (replace, not duplicate)", n2)
	}
	if ovs, _ := s.ListOverrides(ctx, dst, time.Now()); len(ovs) != 1 {
		t.Fatalf("re-copy duplicated overrides: %d live, want 1", len(ovs))
	}
	// Replace clears a rule the destination had that the source lacks.
	otherVeh, _ := s.CreateVehicle(ctx, owner, "BBB222", "Other")
	if err := s.SetRule(ctx, dst, time.Wednesday, otherVeh); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CopySchedule(ctx, owner, src, dst, time.Now()); err != nil {
		t.Fatal(err)
	}
	if rules, _ := s.ListRules(ctx, dst); len(rules) != 2 {
		t.Fatalf("replace should leave only the source's 2 rules, got %d", len(rules))
	}
	// Self-copy is rejected.
	if _, err := s.CopySchedule(ctx, owner, dst, dst, time.Now()); err == nil {
		t.Fatal("self-copy should error")
	}
	// Cross-owner source is rejected (ErrNotFound), copying nothing.
	other, _ := s.UpsertPermit(ctx, "other@example.com", "x-1", "14", "X")
	if _, err := s.CopySchedule(ctx, owner, other, dst, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner copy err = %v, want ErrNotFound", err)
	}
}

// TestSaveReconnectedSessionPreservesLinkedAt: an auto-reconnect refreshes the
// cookie + saved password but must NOT advance linked_at (the 90-day re-authorise
// clock only moves on an interactive re-link).
func TestSaveReconnectedSessionPreservesLinkedAt(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	owner := "rc@example.com"
	if err := s.SaveCouncilSession(ctx, CouncilSession{Owner: owner, Cookie: "c1", Password: "pw1"}); err != nil {
		t.Fatal(err)
	}
	orig, _ := s.GetCouncilSession(ctx, owner)
	if orig.LinkedAt.IsZero() {
		t.Fatal("interactive link should stamp linked_at")
	}
	if !orig.ReconnectedAt.IsZero() {
		t.Fatal("reconnected_at should be zero before any password reconnect")
	}
	if err := s.SaveReconnectedSession(ctx, CouncilSession{Owner: owner, Cookie: "c2", Password: "pw2"}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetCouncilSession(ctx, owner)
	if !got.LinkedAt.Equal(orig.LinkedAt) {
		t.Fatalf("linked_at moved on reconnect: %v -> %v", orig.LinkedAt, got.LinkedAt)
	}
	if got.Cookie != "c2" || got.Password != "pw2" {
		t.Fatalf("reconnect didn't refresh cookie/password: %q / %q", got.Cookie, got.Password)
	}
	// The password replay must be visible to the user: reconnected_at stamps.
	if got.ReconnectedAt.IsZero() {
		t.Fatal("reconnect should stamp reconnected_at")
	}
}

// TestPermitMetaAndExpiryReminder covers persisting the council expiry/status and
// the reminder flag that re-arms when the expiry date changes.
func TestPermitMetaAndExpiryReminder(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	owner := "e@example.com"
	pid, err := s.UpsertPermit(ctx, owner, "555", "14", "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	end := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	if err := s.UpdatePermitMeta(ctx, owner, "555", "Granted", "VPP24714", "(A) 1st Visitor Permit", end); err != nil {
		t.Fatal(err)
	}
	p, _ := s.GetPermit(ctx, pid)
	if p.Status != "Granted" || !p.EndDate.Equal(end) {
		t.Fatalf("meta not persisted: status=%q end=%v", p.Status, p.EndDate)
	}
	if p.PermitNumber != "VPP24714" || p.PermitType != "(A) 1st Visitor Permit" {
		t.Fatalf("number/type not persisted: %q / %q", p.PermitNumber, p.PermitType)
	}
	// Mark reminded; a same-date meta update must preserve the flag.
	if err := s.MarkPermitExpiryReminded(ctx, pid); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdatePermitMeta(ctx, owner, "555", "Granted", "VPP24714", "(A) 1st Visitor Permit", end); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.GetPermit(ctx, pid); !p.ExpiryReminded {
		t.Fatal("same-date update should keep reminded flag")
	}
	// A new expiry date (renewal) clears the flag.
	end2 := end.AddDate(0, 3, 0)
	if err := s.UpdatePermitMeta(ctx, owner, "555", "Granted", "VPP24714", "(A) 1st Visitor Permit", end2); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.GetPermit(ctx, pid); p.ExpiryReminded {
		t.Fatal("changed expiry date should clear reminded flag")
	}
	// Owner scoping: a different owner's update is a no-op.
	if err := s.UpdatePermitMeta(ctx, "other@example.com", "555", "Cancelled", "X", "X", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.GetPermit(ctx, pid); p.Status != "Granted" {
		t.Fatalf("cross-owner update leaked: status=%q", p.Status)
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
	if _, err := s.ConfirmSession(ctx, "wrong", 0); err != ErrNotFound {
		t.Fatalf("ConfirmSession(wrong) err = %v, want ErrNotFound", err)
	}

	got, err := s.ConfirmSession(ctx, "tok-123", 0)
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
	if _, err := s.ConfirmSession(ctx, "tok-123", 0); err != ErrNotFound {
		t.Fatalf("token reuse should fail: %v", err)
	}

	// A token older than maxAge is refused (and cleared), so an unclicked confirm
	// link can't sit in a mailbox as a permanent "keep managing my permit" grant.
	if err := s.MarkReminderSent(ctx, owner, "tok-stale"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE council_session SET reminder_sent_at = ? WHERE owner = ?`,
		time.Now().Add(-30*24*time.Hour).UTC().Format(time.RFC3339), owner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmSession(ctx, "tok-stale", 21*24*time.Hour); err != ErrNotFound {
		t.Fatalf("stale token should be refused: %v", err)
	}
	if cs3, _ := s.GetCouncilSession(ctx, owner); cs3.ConfirmToken != "" {
		t.Fatalf("stale token should be cleared, got %q", cs3.ConfirmToken)
	}
	// Within maxAge it still works.
	if err := s.MarkReminderSent(ctx, owner, "tok-fresh"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ConfirmSession(ctx, "tok-fresh", 21*24*time.Hour); err != nil || got != owner {
		t.Fatalf("fresh token = %q, %v", got, err)
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
		// A queued notification about this account (carries their email + plate).
		if err := s.EnqueueOutbox(ctx, OutboxItem{Account: owner, DedupKey: "d-" + owner, Recipients: []string{owner}, Subject: "S", Body: "B"}); err != nil {
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
	// Alice's queued notification (email + plate) must not survive deletion.
	if due, _ := s.DueOutbox(ctx, time.Now(), 10); len(due) != 1 || due[0].DedupKey != "d-"+bob {
		t.Fatalf("outbox after delete = %+v, want only bob's row", due)
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

func TestGuestBaselineAndOverrideSweep(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const owner = "alice@example.com"
	v, _ := s.CreateVehicle(ctx, owner, "AAA111", "Mum")
	p, _ := s.UpsertPermit(ctx, owner, "P1", "14", "Permit")
	if _, err := s.CreateGuestGrant(ctx, owner, p, "pass", false, []int64{v},
		[]GuestRecipient{{Email: "kid@example.com", TokenHash: "hashK"}}); err != nil {
		t.Fatalf("create grant: %v", err)
	}
	gc, err := s.GuestContextByTokenHash(ctx, "hashK")
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if gc.BaselinePlate != "" || !gc.BaselineUntil.IsZero() {
		t.Fatalf("fresh token should have no baseline, got %q until %v", gc.BaselinePlate, gc.BaselineUntil)
	}

	until := time.Now().Add(6 * time.Hour).Truncate(time.Second)
	if err := s.SetGuestBaseline(ctx, gc.TokenID, "ZZZ999", until); err != nil {
		t.Fatalf("set baseline: %v", err)
	}
	gc, _ = s.GuestContextByTokenHash(ctx, "hashK")
	if gc.BaselinePlate != "ZZZ999" || gc.BaselineUntil.Unix() != until.Unix() {
		t.Fatalf("baseline round-trip = %q until %v, want ZZZ999 until %v", gc.BaselinePlate, gc.BaselineUntil, until)
	}

	// Two guest-tagged overrides and one of the owner's own: the sweep must
	// remove exactly the guest's.
	end := time.Now().Add(4 * time.Hour)
	if _, err := s.CreateGuestOverride(ctx, p, v, time.Now(), &end, "kid", gc.TokenID); err != nil {
		t.Fatalf("guest override: %v", err)
	}
	if _, err := s.CreateGuestPlateOverride(ctx, p, "CCC333", time.Now(), &end, "kid", gc.TokenID); err != nil {
		t.Fatalf("guest plate override: %v", err)
	}
	if _, err := s.CreateOverride(ctx, p, v, time.Now(), &end, owner); err != nil {
		t.Fatalf("owner override: %v", err)
	}
	if err := s.DeleteGuestOverrides(ctx, p, 0); err == nil {
		t.Fatal("sweep with tokenID 0 must be refused")
	}
	if err := s.DeleteGuestOverrides(ctx, p, gc.TokenID); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	ovs, err := s.ListOverrides(ctx, p, time.Now())
	if err != nil || len(ovs) != 1 || ovs[0].CreatedBy != owner {
		t.Fatalf("after sweep want only the owner's override, got %v (%v)", ovs, err)
	}

	if err := s.ClearGuestBaseline(ctx, gc.TokenID); err != nil {
		t.Fatalf("clear baseline: %v", err)
	}
	gc, _ = s.GuestContextByTokenHash(ctx, "hashK")
	if gc.BaselinePlate != "" || !gc.BaselineUntil.IsZero() {
		t.Fatalf("baseline should be cleared, got %q until %v", gc.BaselinePlate, gc.BaselineUntil)
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

func TestResetGuestToken(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const alice, bob = "alice@example.com", "bob@example.com"
	aV, _ := s.CreateVehicle(ctx, alice, "AAA111", "Dad")
	aPermit, _ := s.UpsertPermit(ctx, alice, "P1", "14", "Alice permit")
	grantID, err := s.CreateGuestGrant(ctx, alice, aPermit, "Friday", false, []int64{aV},
		[]GuestRecipient{{Email: "dad@example.com", TokenHash: "hashD"}})
	if err != nil {
		t.Fatal(err)
	}

	// A foreign owner cannot re-send.
	if _, err := s.ResetGuestToken(ctx, bob, grantID, "dad@example.com", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign reset = %v, want ErrNotFound", err)
	}
	// Re-sending to someone who was never a recipient is rejected.
	if _, err := s.ResetGuestToken(ctx, alice, grantID, "stranger@example.com", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown recipient = %v, want ErrNotFound", err)
	}

	// Re-send: the old link stops working, the fresh one resolves, permit returned.
	pid, err := s.ResetGuestToken(ctx, alice, grantID, "dad@example.com", "hashD2")
	if err != nil || pid != aPermit {
		t.Fatalf("reset: pid=%d err=%v (want %d)", pid, err, aPermit)
	}
	if _, err := s.GuestContextByTokenHash(ctx, "hashD"); !errors.Is(err, ErrNotFound) {
		t.Fatal("old link should stop working after re-send")
	}
	gc, err := s.GuestContextByTokenHash(ctx, "hashD2")
	if err != nil || gc.Recipient != "dad@example.com" {
		t.Fatalf("fresh link should resolve to dad: %+v err=%v", gc, err)
	}
	// The recipient still appears exactly once (no lingering duplicate row).
	details, err := s.ListGuestGrants(ctx, alice)
	if err != nil || len(details) != 1 || len(details[0].Tokens) != 1 {
		t.Fatalf("recipient should appear once after re-send: %+v err=%v", details, err)
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
	reqID, _, created, err := s.CreateGuestRequest(ctx, grantID, p, owner, "TRADIE1", "secretnonce")
	if err != nil || !created {
		t.Fatalf("create request: created=%v err=%v", created, err)
	}
	// A second scan of the SAME plate reuses the pending request (no duplicate).
	if id2, n2, created2, err := s.CreateGuestRequest(ctx, grantID, p, owner, "TRADIE1", "othernonce"); err != nil || created2 || id2 != reqID || n2 != "secretnonce" {
		t.Fatalf("re-scan should reuse pending request: id=%d nonce=%q created=%v err=%v", id2, n2, created2, err)
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
	if _, err := s.DecideGuestRequest(ctx, bob, reqID, true, "2026-07-21T00:00:00Z", bob, time.Time{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign decide = %v, want ErrNotFound", err)
	}
	wantEnd := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)
	dec, err := s.DecideGuestRequest(ctx, owner, reqID, true, "2026-07-21T00:00:00Z", owner, wantEnd)
	if err != nil || dec.Status != "approved" || dec.Until != "2026-07-21T00:00:00Z" {
		t.Fatalf("approve = %+v, %v", dec, err)
	}
	if dec.DecidedBy != owner || !dec.UntilTS.Equal(wantEnd) {
		t.Fatalf("decision audit = by %q until %v, want by %q until %v", dec.DecidedBy, dec.UntilTS, owner, wantEnd)
	}
	// Deciding again is a no-op (no longer pending) and drops out of the queue.
	if _, err := s.DecideGuestRequest(ctx, owner, reqID, true, "", owner, time.Time{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-decide = %v, want ErrNotFound", err)
	}
	// The decision shows in the recent list (any window covering now), with the
	// audit fields intact — the feed every account member sees.
	if recent, err := s.ListRecentDecidedRequests(ctx, owner, time.Now().Add(-time.Hour)); err != nil ||
		len(recent) != 1 || recent[0].Plate != "TRADIE1" || recent[0].DecidedBy != owner || recent[0].Status != "approved" {
		t.Fatalf("recent decided = %+v, %v", recent, err)
	}
	if recent, _ := s.ListRecentDecidedRequests(ctx, bob, time.Now().Add(-time.Hour)); len(recent) != 0 {
		t.Fatalf("foreign owner should see no recent decisions, got %d", len(recent))
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

func TestNotifyRosterExcludesDeletedAccount(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const alice, bob = "alice@example.com", "bob@example.com"

	// Two consented accounts; bob also has an ntfy topic.
	if err := s.RecordConsent(ctx, alice, "v1", "h"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordConsent(ctx, bob, "v1", "h"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNotifyPref(ctx, NotifyPref{Owner: bob, EmailEnabled: true, NtfyEnabled: true, NtfyTopic: "bob-topic"}); err != nil {
		t.Fatal(err)
	}
	// Give alice something to cascade so deletion touches more than consent.
	p, _ := s.UpsertPermit(ctx, alice, "P-alice", "14", "Alice permit")
	if _, err := s.CreatePrintedGrant(ctx, alice, p, "ahash", "asealed"); err != nil {
		t.Fatal(err)
	}

	inRoster := func(email string) (RosterEntry, bool) {
		roster, err := s.NotifyRoster(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range roster {
			if e.Email == email {
				return e, true
			}
		}
		return RosterEntry{}, false
	}

	if e, ok := inRoster(bob); !ok || e.Ntfy != "bob-topic" {
		t.Fatalf("bob should be in the roster with his ntfy topic, got %+v ok=%v", e, ok)
	}
	if _, ok := inRoster(alice); !ok {
		t.Fatal("alice should be in the roster before deletion")
	}

	// Deleting alice's account must drop her from the outage-notify roster.
	if err := s.DeleteAllForOwner(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if _, ok := inRoster(alice); ok {
		t.Fatal("deleted account must not remain in the notify roster")
	}
	if _, ok := inRoster(bob); !ok {
		t.Fatal("bob should still be in the roster")
	}
	// Her guest grant (and token) must be gone too, so a leaked token can't resolve.
	if _, err := s.GuestContextByTokenHash(ctx, "ahash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted account's guest token still resolves = %v, want ErrNotFound", err)
	}
}

func TestOutbox(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.EnqueueOutbox(ctx, OutboxItem{Recipients: []string{"a@x.co"}, Subject: "S1", Body: "B1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueOutbox(ctx, OutboxItem{DedupKey: "k1", NtfyTopic: "topic", Subject: "S2", Body: "B2"}); err != nil {
		t.Fatal(err)
	}
	// Idempotency: a second enqueue with the same dedup key is a no-op.
	if err := s.EnqueueOutbox(ctx, OutboxItem{DedupKey: "k1", Subject: "dup", Body: "dup"}); err != nil {
		t.Fatal(err)
	}

	due, err := s.DueOutbox(ctx, time.Now(), 10)
	if err != nil || len(due) != 2 {
		t.Fatalf("due = %d (%v), want 2 (dedup dropped the third)", len(due), err)
	}
	// Recipients round-trip through the newline encoding.
	s1 := due[0]
	if s1.Subject != "S1" || len(s1.Recipients) != 1 || s1.Recipients[0] != "a@x.co" {
		t.Fatalf("recipients round-trip: %+v", s1)
	}

	// Reschedule S1 into the future → not due now, due later.
	if err := s.RescheduleOutbox(ctx, s1.ID, 1, time.Now().Add(time.Hour), "boom"); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.DueOutbox(ctx, time.Now(), 10); len(d) != 1 {
		t.Fatalf("after reschedule, due now = %d, want 1", len(d))
	}
	if d, _ := s.DueOutbox(ctx, time.Now().Add(2*time.Hour), 10); len(d) != 2 {
		t.Fatalf("after reschedule, due in 2h = %d, want 2", len(d))
	}

	// Sent and dead both drop out of the due set (survives restart: it's all in SQLite).
	if err := s.MarkOutboxSent(ctx, s1.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkOutboxDead(ctx, due[1].ID, "gave up"); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.DueOutbox(ctx, time.Now().Add(2*time.Hour), 10); len(d) != 0 {
		t.Fatalf("after sent+dead, due = %d, want 0", len(d))
	}

	// Purge removes both the delivered row and the dead one (PII hygiene): a
	// dead-lettered message still carries recipient email + plate, so it must not
	// linger indefinitely.
	n, err := s.PurgeSentOutbox(ctx, time.Now().Add(24*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("purge = %d (%v), want 2 (sent + dead)", n, err)
	}
}

// TestOutboxNotBefore covers quiet-hours deferral: an item enqueued with a future
// NotBefore isn't due until then; a zero/past NotBefore is due immediately.
func TestOutboxNotBefore(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	future := time.Now().Add(90 * time.Minute)
	if err := s.EnqueueOutbox(ctx, OutboxItem{DedupKey: "held", Recipients: []string{"a@x.co"}, Subject: "held", Body: "B", NotBefore: future}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueOutbox(ctx, OutboxItem{DedupKey: "now", Recipients: []string{"a@x.co"}, Subject: "now", Body: "B"}); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.DueOutbox(ctx, time.Now(), 10); len(d) != 1 || d[0].DedupKey != "now" {
		t.Fatalf("due now = %+v, want only the immediate one", d)
	}
	if d, _ := s.DueOutbox(ctx, time.Now().Add(2*time.Hour), 10); len(d) != 2 {
		t.Fatalf("due after the hold window = %d, want 2", len(d))
	}
}

// TestOutboxDedupWindow locks in the fix that a delivered notice only suppresses
// re-enqueues of the same key for a short window, so a legitimately repeated
// outcome (an alternating A/B/A roster, a recurring failure) still sends rather
// than being silently dropped against a week-old sent row.
func TestOutboxDedupWindow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	countKey := func() int {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE dedup_key = 'k'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	enq := func() {
		if err := s.EnqueueOutbox(ctx, OutboxItem{DedupKey: "k", Recipients: []string{"a@x.co"}, Subject: "S", Body: "B"}); err != nil {
			t.Fatal(err)
		}
	}

	enq()
	enq() // while pending, the duplicate is deduped
	if countKey() != 1 {
		t.Fatalf("pending dedup: %d rows, want 1", countKey())
	}

	// Deliver it, then backdate sent_at beyond the dedup window.
	due, _ := s.DueOutbox(ctx, time.Now(), 10)
	if len(due) != 1 {
		t.Fatalf("due = %d, want 1", len(due))
	}
	if err := s.MarkOutboxSent(ctx, due[0].ID); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-outboxDedupWindow - time.Minute).UTC().Format(time.RFC3339)
	if _, err := s.db.ExecContext(ctx, `UPDATE outbox SET sent_at = ? WHERE id = ?`, old, due[0].ID); err != nil {
		t.Fatal(err)
	}

	// A later occurrence of the same outcome now re-enqueues (the bug was: it was
	// dropped against the old sent row for 7 days).
	enq()
	if countKey() != 2 {
		t.Fatalf("after-window re-enqueue: %d rows, want 2", countKey())
	}

	// But a sent row still WITHIN the window keeps deduping (absorbs a double-tap).
	due2, _ := s.DueOutbox(ctx, time.Now(), 10)
	if len(due2) != 1 {
		t.Fatalf("second due = %d, want 1", len(due2))
	}
	if err := s.MarkOutboxSent(ctx, due2[0].ID); err != nil { // sent_at = now (recent)
		t.Fatal(err)
	}
	enq()
	if countKey() != 2 {
		t.Fatalf("within-window dedup: %d rows, want 2 (the recent duplicate suppressed)", countKey())
	}
}

// TestActiveGuestOverridePlate covers the helper that gates the guest "put it
// back" offer: it returns this link's own live override plate, and nothing once
// that override has ended or been swept.
func TestActiveGuestOverridePlate(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const owner = "o@example.com"
	pid, err := s.UpsertPermit(ctx, owner, "VPP1", "1", "VPP1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	end := now.Add(6 * time.Hour)

	// A zero token id is refused (would match every non-guest override).
	if _, ok := s.ActiveGuestOverridePlate(ctx, pid, 0, now); ok {
		t.Fatal("zero token id must not match")
	}

	// This link's live override is reported.
	if _, err := s.CreateGuestPlateOverride(ctx, pid, "GST111", now.Add(-time.Minute), &end, "visitor", 42); err != nil {
		t.Fatal(err)
	}
	if reg, ok := s.ActiveGuestOverridePlate(ctx, pid, 42, now); !ok || reg != "GST111" {
		t.Fatalf("active override = %q,%v, want GST111,true", reg, ok)
	}
	// A different token sees nothing.
	if _, ok := s.ActiveGuestOverridePlate(ctx, pid, 99, now); ok {
		t.Fatal("another token must not see this link's override")
	}
	// After the window ends, nothing is active.
	if _, ok := s.ActiveGuestOverridePlate(ctx, pid, 42, end.Add(time.Minute)); ok {
		t.Fatal("an ended override must not be reported")
	}
	// Swept overrides disappear.
	if err := s.DeleteGuestOverrides(ctx, pid, 42); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ActiveGuestOverridePlate(ctx, pid, 42, now); ok {
		t.Fatal("a swept override must not be reported")
	}
}

// Regression: AdminAccounts used to hold pointers into the result slice while
// still appending to it; once append reallocated, the plate fold-in wrote into
// the abandoned backing array and most accounts came back with no plates.
func TestAdminAccountsPlatesSurviveSliceGrowth(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	owners := []string{"a@x.com", "b@x.com", "c@x.com", "d@x.com", "e@x.com"}
	for i, owner := range owners {
		pid, err := s.UpsertPermit(ctx, owner, "CP-"+owner, "type", "Permit")
		if err != nil {
			t.Fatal(err)
		}
		reg := []string{"AAA000", "BBB111", "CCC222", "DDD333", "EEE444"}[i]
		if err := s.SetPermitActive(ctx, pid, reg); err != nil {
			t.Fatal(err)
		}
	}
	accounts, err := s.AdminAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != len(owners) {
		t.Fatalf("got %d accounts, want %d", len(accounts), len(owners))
	}
	for _, a := range accounts {
		if len(a.Plates) != 1 {
			t.Errorf("account %s has plates %v, want exactly one", a.Owner, a.Plates)
		}
	}
}

// Regression: for a database old enough to lack override.registration, the
// table rebuild ran AFTER the ALTER loop had added guest_token_id but recreated
// the table without it — every guest-override insert then failed with "no such
// column" until the next restart re-added it. Start from the true legacy schema
// and assert the migrated table accepts a guest override.
func TestMigrateLegacyOverrideTableKeepsGuestTokenID(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Hand-build the legacy override table (NOT NULL vehicle_id, no
	// registration, no guest_token_id) plus the tables it references, so
	// migrate()'s CREATE IF NOT EXISTS keeps them and the rebuild path runs.
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE permit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL,
    council_permit_id TEXT NOT NULL UNIQUE,
    permit_type_id TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL DEFAULT '',
    active_registration TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ''
)`,
		`CREATE TABLE vehicle (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL,
    registration TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ''
)`,
		`CREATE TABLE override (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id INTEGER NOT NULL REFERENCES permit(id) ON DELETE CASCADE,
    vehicle_id INTEGER NOT NULL REFERENCES vehicle(id) ON DELETE CASCADE,
    starts_at TEXT NOT NULL,
    ends_at TEXT,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
)`,
		`INSERT INTO permit (owner, council_permit_id) VALUES ('a@x.com', 'CP-1')`,
		`INSERT INTO vehicle (owner, registration) VALUES ('a@x.com', 'AAA111')`,
		`INSERT INTO override (permit_id, vehicle_id, starts_at, created_at)
    VALUES (1, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("legacy setup %q: %v", stmt, err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("migrate legacy db: %v", err)
	}
	defer s.Close()

	// The pre-existing row must survive the rebuild.
	if has, err := s.columnExists("override", "guest_token_id"); err != nil || !has {
		t.Fatalf("guest_token_id missing after migration (err=%v)", err)
	}
	// And a guest override must be insertable in THIS process, not just after
	// another restart.
	end := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	if _, err := s.CreateGuestPlateOverride(ctx, 1, "BBB222", time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), &end, "guest", 7); err != nil {
		t.Fatalf("guest override insert after legacy migration: %v", err)
	}
}

// oauth_state rows are written by unauthenticated visitors: they must be
// single-use (atomic take), expire, and get swept rather than accumulate.
func TestOAuthStateLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.PutOAuthState(ctx, "st1", "ver", "non", "app"); err != nil {
		t.Fatal(err)
	}
	got, err := s.TakeOAuthState(ctx, "st1")
	if err != nil || got.Verifier != "ver" || got.Nonce != "non" || got.Kind != "app" {
		t.Fatalf("take = %+v, %v", got, err)
	}
	// Single use: the second take must miss.
	if _, err := s.TakeOAuthState(ctx, "st1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second take err = %v, want ErrNotFound", err)
	}

	// Expired: backdate a row past the TTL; it must not be redeemable and the
	// next Put must sweep it.
	if err := s.PutOAuthState(ctx, "old", "v", "n", "app"); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().UTC().Add(-oauthStateTTL - time.Minute).Format(time.RFC3339)
	if _, err := s.db.ExecContext(ctx, `UPDATE oauth_state SET created_at = ? WHERE state = 'old'`, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeOAuthState(ctx, "old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired take err = %v, want ErrNotFound", err)
	}
	if err := s.PutOAuthState(ctx, "fresh", "v", "n", "app"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_state WHERE state = 'old'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("expired oauth_state row was not swept by Put")
	}
}

// The door QR is public: pending requests must dedup per plate, cap per grant,
// expire when unanswered, and purge (visitor plates are PII) once decided.
func TestGuestRequestCapExpiryAndPurge(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const owner = "alice@example.com"
	v, _ := s.CreateVehicle(ctx, owner, "AAA111", "Mum")
	p, _ := s.UpsertPermit(ctx, owner, "P1", "14", "Permit")
	gid, err := s.CreateGuestGrant(ctx, owner, p, "door", false, []int64{v},
		[]GuestRecipient{{Email: "door@example.com", TokenHash: "hashD"}})
	if err != nil {
		t.Fatal(err)
	}

	// Same plate re-scan reuses the pending request.
	id1, n1, created, err := s.CreateGuestRequest(ctx, gid, p, owner, "AAA111", "nonce1")
	if err != nil || !created {
		t.Fatalf("first request: id=%d created=%v err=%v", id1, created, err)
	}
	id2, n2, created, err := s.CreateGuestRequest(ctx, gid, p, owner, "AAA111", "nonce2")
	if err != nil || created || id2 != id1 || n2 != n1 {
		t.Fatalf("re-scan should reuse: id=%d created=%v err=%v", id2, created, err)
	}

	// Distinct plates fill the cap; one more is refused.
	for i := 0; i < maxPendingGuestRequests-1; i++ {
		plate := "BBB10" + string(rune('0'+i))
		if _, _, _, err := s.CreateGuestRequest(ctx, gid, p, owner, plate, "n"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if _, _, _, err := s.CreateGuestRequest(ctx, gid, p, owner, "ZZZ999", "n"); !errors.Is(err, ErrGuestRequestLimit) {
		t.Fatalf("over-cap err = %v, want ErrGuestRequestLimit", err)
	}
	// But an existing plate still resolves to its pending row at the cap.
	if id, _, created, err := s.CreateGuestRequest(ctx, gid, p, owner, "AAA111", "n"); err != nil || created || id != id1 {
		t.Fatalf("dup at cap: id=%d created=%v err=%v", id, created, err)
	}

	// Expiry: age everything past the TTL; pending rows become expired (which a
	// decide can no longer touch) and the cap frees up.
	if _, err := s.db.ExecContext(ctx, `UPDATE guest_request SET requested_at = '2020-01-01T00:00:00Z'`); err != nil {
		t.Fatal(err)
	}
	n, err := s.ExpireGuestRequests(ctx, time.Now().Add(-time.Hour))
	if err != nil || n != int64(maxPendingGuestRequests) {
		t.Fatalf("expired %d, err=%v; want %d", n, err, maxPendingGuestRequests)
	}
	if _, err := s.DecideGuestRequest(ctx, owner, id1, true, "today", owner, time.Time{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deciding an expired request must fail, got %v", err)
	}
	if _, _, created, err := s.CreateGuestRequest(ctx, gid, p, owner, "ZZZ999", "n"); err != nil || !created {
		t.Fatalf("cap should free after expiry: created=%v err=%v", created, err)
	}

	// Purge: decided/expired rows older than the window are deleted.
	if _, err := s.PurgeDecidedGuestRequests(ctx, time.Now().Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM guest_request`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 1 { // only the fresh ZZZ999 pending row remains
		t.Fatalf("rows after purge = %d, want 1", left)
	}
}

// TestSuppression covers the mail suppression list: a complaint outranks a
// bounce (it is the signal with legal weight and the recipient's own request),
// lookups and annotation are case-insensitive, and clearing works.
func TestSuppression(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if bad, _, err := s.IsSuppressed(ctx, "nobody@example.com"); err != nil || bad {
		t.Fatalf("unknown address suppressed=%v err=%v", bad, err)
	}

	if err := s.SuppressAddress(ctx, "Dead@Example.com", SuppressBounce, "550 user unknown"); err != nil {
		t.Fatal(err)
	}
	// Stored and matched lower-cased, so the same mailbox typed differently hits.
	bad, reason, err := s.IsSuppressed(ctx, "dead@example.com")
	if err != nil || !bad || reason != SuppressBounce {
		t.Fatalf("IsSuppressed = %v/%q, err=%v", bad, reason, err)
	}

	// A repeat report bumps the counter rather than duplicating the row.
	if err := s.SuppressAddress(ctx, "dead@example.com", SuppressBounce, "again"); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListSuppressions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Hits != 2 {
		t.Fatalf("expected one row with 2 hits, got %+v", list)
	}

	// A complaint upgrades a bounce...
	if err := s.SuppressAddress(ctx, "dead@example.com", SuppressComplaint, "abuse"); err != nil {
		t.Fatal(err)
	}
	if _, reason, _ := s.IsSuppressed(ctx, "dead@example.com"); reason != SuppressComplaint {
		t.Fatalf("complaint should outrank bounce, got %q", reason)
	}
	// ...and a later bounce must NOT downgrade it back.
	if err := s.SuppressAddress(ctx, "dead@example.com", SuppressBounce, "550"); err != nil {
		t.Fatal(err)
	}
	if _, reason, _ := s.IsSuppressed(ctx, "dead@example.com"); reason != SuppressComplaint {
		t.Fatalf("bounce must not downgrade a complaint, got %q", reason)
	}

	// SuppressedAmong annotates a list in one query, keyed by the caller's spelling.
	got, err := s.SuppressedAmong(ctx, []string{"DEAD@example.com", "fine@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["DEAD@example.com"] != SuppressComplaint {
		t.Fatalf("SuppressedAmong = %+v", got)
	}

	if err := s.Unsuppress(ctx, "dead@example.com"); err != nil {
		t.Fatal(err)
	}
	if bad, _, _ := s.IsSuppressed(ctx, "dead@example.com"); bad {
		t.Fatal("Unsuppress did not clear the address")
	}
}
