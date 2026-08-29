package store

import (
	"context"
	"testing"
	"time"
)

// backdateConsent rewrites every consent row for owner to the given moment.
// RecordConsent stamps time.Now by design; the nudge query keys on age, so
// tests must move the clock rather than wait a day.
func backdateConsent(t *testing.T, s *Store, owner string, at time.Time) {
	t.Helper()
	if _, err := s.db.Exec(`UPDATE consent SET agreed_at = ? WHERE owner = ?`,
		at.UTC().Format(time.RFC3339), owner); err != nil {
		t.Fatalf("backdate consent for %s: %v", owner, err)
	}
}

func consentAt(t *testing.T, s *Store, owner string, at time.Time) {
	t.Helper()
	if err := s.RecordConsent(context.Background(), owner, "v1", "hash"); err != nil {
		t.Fatalf("consent for %s: %v", owner, err)
	}
	backdateConsent(t, s, owner, at)
}

// TestOnboardNudgeCandidates pins the audience of the once-ever recovery email:
// signed up inside the window, and stalled before ever connecting the tenant —
// with each exclusion representing a person who is NOT stalled at that step.
// Mailing any of them "you're one step away" would range from confusing (a
// secondary, who has no tenant account to link) to false (a linked household).
func TestOnboardNudgeCandidates(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now()
	oldest, newest := now.Add(-14*24*time.Hour), now.Add(-24*time.Hour)
	twoDaysAgo := now.Add(-2 * 24 * time.Hour)

	// The one genuine candidate: consented two days ago, nothing else on file.
	consentAt(t, s, "stalled@example.com", twoDaysAgo)

	// Saved vehicles must NOT exclude — adding cars then failing at the tenant
	// password is exactly the stall the email unsticks.
	consentAt(t, s, "cars-only@example.com", twoDaysAgo)
	if _, err := s.CreateVehicle(ctx, "cars-only@example.com", "AAA111", "car", ""); err != nil {
		t.Fatal(err)
	}

	// Too fresh: signed up an hour ago; give them their day before emailing.
	consentAt(t, s, "fresh@example.com", now.Add(-time.Hour))

	// Too old: predates the lookback; "almost there!" months later reads as spam.
	consentAt(t, s, "ancient@example.com", now.Add(-30*24*time.Hour))

	// Currently linked: a tenant_session row is a working connection.
	consentAt(t, s, "linked@example.com", twoDaysAgo)
	if _, err := s.db.Exec(`INSERT INTO council_session (owner) VALUES (?)`, "linked@example.com"); err != nil {
		t.Fatal(err)
	}

	// Holds a permit: they connected once and picked one — a lapsed session here
	// is the relink flow's job, which has its own reminders.
	consentAt(t, s, "haspermit@example.com", twoDaysAgo)
	if _, err := s.UpsertPermit(ctx, "haspermit@example.com", "C-1", "T-1", "VPP1"); err != nil {
		t.Fatal(err)
	}

	// Linked at least once in the past (change log), even though session and
	// permits are gone now: they know the way in; they left on purpose.
	consentAt(t, s, "oncelinked@example.com", twoDaysAgo)
	if err := s.RecordChange(ctx, "oncelinked@example.com", "oncelinked@example.com", ActionCouncilLink, "", ""); err != nil {
		t.Fatal(err)
	}

	// An accepted secondary shares the primary's connection; there is nothing
	// for them to link. (AddMember writes an ACTIVE row — the pending state is
	// AddMemberCapped's, below.)
	consentAt(t, s, "secondary@example.com", twoDaysAgo)
	if err := s.AddMember(ctx, "someprimary@example.com", "secondary@example.com"); err != nil {
		t.Fatal(err)
	}

	// A merely PENDING invite grants nothing and proves nothing — this person
	// may be a stalled signup in their own right, so they stay a candidate.
	consentAt(t, s, "invited@example.com", twoDaysAgo)
	if err := s.AddMemberCapped(ctx, "someprimary@example.com", "invited@example.com", 5); err != nil {
		t.Fatal(err)
	}

	got, err := s.OnboardNudgeCandidates(ctx, oldest, newest)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"stalled@example.com":   true,
		"cars-only@example.com": true,
		"invited@example.com":   true,
	}
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want exactly %v", got, want)
	}
	for _, o := range got {
		if !want[o] {
			t.Errorf("unexpected candidate %s", o)
		}
	}

	// Marking removes a candidate permanently — the "once ever" in the email's
	// own promise ("this is the only reminder p.stonn sends").
	if err := s.MarkOnboardNudgeSent(ctx, "stalled@example.com"); err != nil {
		t.Fatal(err)
	}
	got, err = s.OnboardNudgeCandidates(ctx, oldest, newest)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range got {
		if o == "stalled@example.com" {
			t.Fatal("marked owner still a candidate; the once-ever email would repeat")
		}
	}

	// The mark must coexist with an account_flags row that already exists for
	// the guests kill-switch (same table, different column, upsert not insert).
	if err := s.SetGuestsEnabled(ctx, "cars-only@example.com", false); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkOnboardNudgeSent(ctx, "cars-only@example.com"); err != nil {
		t.Fatal(err)
	}
	if on, err := s.GuestsEnabled(ctx, "cars-only@example.com"); err != nil || on {
		t.Fatalf("nudge mark clobbered guests_enabled: on=%v err=%v", on, err)
	}
	got, err = s.OnboardNudgeCandidates(ctx, oldest, newest)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "invited@example.com" {
		t.Fatalf("candidates after marks = %v, want just invited@example.com", got)
	}

	// Re-acceptance after a terms change must not re-open the window: the FIRST
	// acceptance is the signup moment, however recent the latest one is.
	backdateConsent(t, s, "ancient@example.com", now.Add(-30*24*time.Hour)) // keep original old
	if err := s.RecordConsent(ctx, "ancient@example.com", "v2", "hash2"); err != nil {
		t.Fatal(err)
	}
	got, err = s.OnboardNudgeCandidates(ctx, oldest, newest)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range got {
		if o == "ancient@example.com" {
			t.Fatal("a terms re-accept re-opened the nudge window for an ancient signup")
		}
	}
}
