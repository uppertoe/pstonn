package store

import (
	"context"
	"time"
)

// HouseholdName is what visitors see in place of the holder's email on guest
// links and QR pages. Empty means the pages name only the permit.
func (s *Store) HouseholdName(ctx context.Context, owner string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT household_name FROM account_flags WHERE owner = ?), '')`, owner).Scan(&v)
	return v, err
}

// SetHouseholdName stores the visitor-facing name; empty clears it.
func (s *Store) SetHouseholdName(ctx context.Context, owner, name string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO account_flags (owner, household_name) VALUES (?, ?)
ON CONFLICT(owner) DO UPDATE SET household_name = excluded.household_name`, owner, name)
	return err
}

// LinkFailureReason is the class of a link attempt that did not produce a
// session. Deliberately coarse: it is the difference between "the council said
// no" and "the council was unreachable", which is what decides whether the
// person needs help or a later retry. The council's own message never lands
// here, and neither does anything the person typed.
type LinkFailureReason string

const (
	LinkFailRejected LinkFailureReason = "rejected" // no session came back: wrong password, or no portal account at all
	LinkFailBusy     LinkFailureReason = "busy"     // the portal pushed back; the password was never judged
	LinkFailShape    LinkFailureReason = "shape"    // the sign-in page no longer matches the login replay
	LinkFailOther    LinkFailureReason = "other"    // anything else, including our own end
)

// NoteLinkFailure records one unsuccessful attempt to link a council account.
// The count is the number that matters — a single rejection is a typo, a run of
// them is someone who cannot get in — so this increments rather than overwrites,
// and keeps the most recent reason alongside it. Best-effort by design: the
// caller has already answered the person, so a write failure here is logged and
// swallowed rather than turned into their problem.
func (s *Store) NoteLinkFailure(ctx context.Context, owner string, reason LinkFailureReason) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO account_flags (owner, link_fail_count, link_fail_last, link_fail_reason) VALUES (?, 1, ?, ?)
ON CONFLICT(owner) DO UPDATE SET
  link_fail_count  = link_fail_count + 1,
  link_fail_last   = excluded.link_fail_last,
  link_fail_reason = excluded.link_fail_reason`, owner, nowUTC(), string(reason))
	return err
}

// LinkFailures reports how many link attempts have failed for owner, when the
// last one was (” = never), and its reason class.
func (s *Store) LinkFailures(ctx context.Context, owner string) (count int, last string, reason string, err error) {
	err = s.db.QueryRowContext(ctx, `
SELECT COALESCE((SELECT link_fail_count  FROM account_flags WHERE owner = ?), 0),
       COALESCE((SELECT link_fail_last   FROM account_flags WHERE owner = ?), ''),
       COALESCE((SELECT link_fail_reason FROM account_flags WHERE owner = ?), '')`,
		owner, owner, owner).Scan(&count, &last, &reason)
	return count, last, reason, err
}

// ClearLinkFailures resets the tally once a link succeeds, so the count always
// means "attempts since the last time this account got in" rather than an
// ever-growing lifetime total that no longer describes anything.
func (s *Store) ClearLinkFailures(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE account_flags SET link_fail_count = 0, link_fail_reason = '' WHERE owner = ?`, owner)
	return err
}

// InactionNudgeAllowed reports whether this account may be told that someone has
// not acted — an invitation unaccepted, a guest pass unused — given the last such
// note went out no later than `notAfter`.
//
// Scoped to those two on purpose. They can genuinely be about the SAME person
// (one household had both an unanswered invitation and two unused passes, all
// three addressed to the same carer), so landing them a day apart reads as
// nagging about one fact twice. The onboard, portal and fortnight notes are
// different concerns and cannot co-occur with these anyway — onboard requires no
// council session, portal requires no successful apply, fortnight requires one —
// so they are deliberately left out rather than paced against each other.
func (s *Store) InactionNudgeAllowed(ctx context.Context, owner string, notAfter time.Time) (bool, error) {
	var last string
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT last_nudge_at FROM account_flags WHERE owner = ?), '')`, owner).Scan(&last); err != nil {
		return false, err
	}
	return last == "" || last <= notAfter.UTC().Format(time.RFC3339), nil
}

// MarkInactionNudged records that this account has just been told someone has
// not acted, starting the gap before the other such note may follow.
//
// The instant is the CALLER'S, not the store's wall clock: the scheduler owns a
// clock its tests move, and a hidden nowUTC() here made the gap untestable —
// a sweep run at a faked time wrote a real timestamp, so the very check this
// column exists for always passed.
func (s *Store) MarkInactionNudged(ctx context.Context, owner string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO account_flags (owner, last_nudge_at) VALUES (?, ?)
ON CONFLICT(owner) DO UPDATE SET last_nudge_at = excluded.last_nudge_at`,
		owner, at.UTC().Format(time.RFC3339))
	return err
}
