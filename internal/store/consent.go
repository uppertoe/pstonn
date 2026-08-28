package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ---- Terms consent ----

// Consent is one recorded acceptance of the terms.
type Consent struct {
	Owner    string
	Version  string
	Hash     string
	AgreedAt time.Time
}

// RecordConsent appends an acceptance of the given terms version/hash.
func (s *Store) RecordConsent(ctx context.Context, owner, version, hash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO consent (owner, version, hash, agreed_at) VALUES (?, ?, ?, ?)`,
		owner, version, hash, nowUTC())
	return err
}

// LatestConsent returns the user's most recent acceptance, or ErrNotFound.
func (s *Store) LatestConsent(ctx context.Context, owner string) (Consent, error) {
	var c Consent
	var at string
	err := s.db.QueryRowContext(ctx,
		`SELECT owner, version, hash, agreed_at FROM consent WHERE owner = ? ORDER BY id DESC LIMIT 1`, owner).
		Scan(&c.Owner, &c.Version, &c.Hash, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.AgreedAt, _ = time.Parse(time.RFC3339, at)
	return c, nil
}

// ---- Onboarding nudge ----

// OnboardNudgeCandidates lists people who signed up (accepted terms) inside the
// [oldest, newest] window and then stalled before ever connecting a council
// account — the once-ever recovery email's audience.
//
// The window has two jobs. The newest bound gives a fresh signup a day to finish
// on their own before being emailed; the oldest bound keeps the first deploy of
// this feature from mailing every abandoned signup back to the beginning of
// time, for whom an "almost there!" email months later reads as spam.
//
// "Never connected" is deliberately strict — each exclusion is a different way
// the person turns out not to be stalled at the link step:
//   - a council_session row: they are connected right now;
//   - a permit row: they connected once and picked a permit (a lapsed session
//     here is the RELINK flow, which has its own reminders);
//   - a council.link entry in account_log: they connected at least once, even
//     if they since disconnected and removed everything;
//   - an accepted membership: a secondary shares the primary's connection and
//     has no council account of their own to link (a still-pending invite does
//     not count — that person may well be a stalled signup of their own);
//   - a recorded nudge: this email is once ever, not once per sweep.
//
// Saved vehicles do NOT exclude: adding cars and then failing at the council
// password is precisely the stall this email exists to unstick.
func (s *Store) OnboardNudgeCandidates(ctx context.Context, oldest, newest time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT c.owner, MIN(c.agreed_at) AS first_agreed
FROM consent c
WHERE NOT EXISTS (SELECT 1 FROM council_session s WHERE s.owner = c.owner)
  AND NOT EXISTS (SELECT 1 FROM permit p WHERE p.owner = c.owner)
  AND NOT EXISTS (SELECT 1 FROM account_log l WHERE l.owner = c.owner AND l.action = ?)
  AND NOT EXISTS (SELECT 1 FROM account_member m WHERE m.member_email = c.owner AND m.invite_pending = 0)
  AND COALESCE((SELECT f.onboard_nudge_sent FROM account_flags f WHERE f.owner = c.owner), '') = ''
GROUP BY c.owner
HAVING first_agreed >= ? AND first_agreed <= ?
ORDER BY first_agreed`,
		ActionCouncilLink, oldest.UTC().Format(time.RFC3339), newest.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var owners []string
	for rows.Next() {
		var owner, at string
		if err := rows.Scan(&owner, &at); err != nil {
			return nil, err
		}
		owners = append(owners, owner)
	}
	return owners, rows.Err()
}

// MarkOnboardNudgeSent records that the once-ever onboarding email went to this
// owner, so no later sweep repeats it.
func (s *Store) MarkOnboardNudgeSent(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO account_flags (owner, onboard_nudge_sent) VALUES (?, ?)
ON CONFLICT(owner) DO UPDATE SET onboard_nudge_sent = excluded.onboard_nudge_sent`,
		owner, nowUTC())
	return err
}

// FortnightNudgeCandidates lists owners whose FIRST successful council write is
// at least `after` old and who have not had the once-ever "tell a neighbour"
// note. Keyed to the first success, not signup: the note only makes sense once
// the product has actually done something for them.
func (s *Store) FortnightNudgeCandidates(ctx context.Context, before time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT p.owner, MIN(a.at) AS first_ok
FROM apply_log a JOIN permit p ON p.id = a.permit_id
WHERE a.status = 'success'
  AND EXISTS (SELECT 1 FROM consent c WHERE c.owner = p.owner)
  AND COALESCE((SELECT f.fortnight_nudge_sent FROM account_flags f WHERE f.owner = p.owner), '') = ''
GROUP BY p.owner
HAVING first_ok <= ?
ORDER BY first_ok`, before.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var owners []string
	for rows.Next() {
		var owner, at string
		if err := rows.Scan(&owner, &at); err != nil {
			return nil, err
		}
		owners = append(owners, owner)
	}
	return owners, rows.Err()
}

// MarkFortnightNudgeSent records the once-ever note as done for owner.
func (s *Store) MarkFortnightNudgeSent(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO account_flags (owner, fortnight_nudge_sent) VALUES (?, ?)
ON CONFLICT(owner) DO UPDATE SET fortnight_nudge_sent = excluded.fortnight_nudge_sent`,
		owner, nowUTC())
	return err
}
