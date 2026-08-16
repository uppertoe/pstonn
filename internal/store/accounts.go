package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// DeleteAllForOwner erases every trace of an app user: their council session,
// permits (cascading rules and overrides), vehicles, and apply-log rows. Used by
// the self-service "delete my data" action. Runs in one transaction so a partial
// failure leaves nothing half-deleted.
func (s *Store) DeleteAllForOwner(ctx context.Context, owner string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// apply_log and permit_notify have no FK cascade; clear the owner's rows
	// before their permits go.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM apply_log WHERE permit_id IN (SELECT id FROM permit WHERE owner = ?)`, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM permit_notify WHERE permit_id IN (SELECT id FROM permit WHERE owner = ?)`, owner); err != nil {
		return err
	}
	// Deleting permits cascades weekly_rule and override (ON DELETE CASCADE).
	if _, err := tx.ExecContext(ctx, `DELETE FROM permit WHERE owner = ?`, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vehicle WHERE owner = ?`, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM council_session WHERE owner = ?`, owner); err != nil {
		return err
	}
	// Notification prefs are per-person: drop this account owner's own row AND the
	// rows of its secondaries (still present in account_member at this point), so a
	// deleted account leaves no member's channel prefs behind.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM notify_pref WHERE owner = ? OR owner IN (SELECT member_email FROM account_member WHERE owner = ?)`,
		owner, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM consent WHERE owner = ?`, owner); err != nil {
		return err
	}
	// Guest passes / door QRs (cascades their tokens, vehicle joins and requests via
	// FK) and the per-account guest flags, so a deleted account leaves nothing behind
	// that could still resolve a token, and drops off the outage-notify roster.
	if _, err := tx.ExecContext(ctx, `DELETE FROM guest_grant WHERE owner = ?`, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM guest_request WHERE owner = ?`, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM account_flags WHERE owner = ?`, owner); err != nil {
		return err
	}
	// Queued/sent/dead notifications about this account (they carry the user's email
	// and plate), so nothing pending is delivered to a deleted user and no PII lingers.
	if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE account = ?`, owner); err != nil {
		return err
	}
	// The change log names people and plates, so it goes with the account.
	if _, err := tx.ExecContext(ctx, `DELETE FROM account_log WHERE owner = ?`, owner); err != nil {
		return err
	}
	// The owner's own address on the suppression list: it is their personal data,
	// and a returning user must not inherit a stale "we don't email you" flag.
	// Guest/driver addresses are deliberately KEPT: they belong to third parties,
	// and a bounce or complaint is a fact about that mailbox, not about this
	// account — forgetting it would resume mailing someone who asked us to stop.
	if _, err := tx.ExecContext(ctx, `DELETE FROM mail_suppression WHERE address = ?`, owner); err != nil {
		return err
	}
	// Remove this account's secondary members, and any membership this user held.
	if _, err := tx.ExecContext(ctx, `DELETE FROM account_member WHERE owner = ? OR member_email = ?`, owner, owner); err != nil {
		return err
	}
	// Their traces on OTHER people's accounts. Everything above is scoped to rows
	// this account owns, but a user who was a secondary elsewhere also left their
	// email address in that household's records — deleting "everything" has to mean
	// that too, not just their own side.
	//
	// Guest passes they minted as a secondary are the security-relevant one: those
	// are bearer links over someone else's permit, and after this delete the primary
	// could no longer see them in Settings to revoke. Mirrors revokeGrantsBy.
	//
	// Sweep their live bookings FIRST. The delete cascades the token rows away, and
	// override.guest_token_id has no foreign key, so afterwards a visitor's plate is
	// left steering someone ELSE's permit with nothing able to reach it: the primary's
	// revoke, delete-pass and account-wide pause all match through guest_token, and the
	// pass has vanished from their Settings page entirely. They would be left with a
	// stranger's plate on their permit for up to two days, every control reporting
	// success. This is what "Mirrors revokeGrantsBy" was always meant to mean.
	if _, err := tx.ExecContext(ctx, sweepLiveGuestOverrides+`IN (
        SELECT t.id FROM guest_token t JOIN guest_grant g ON g.id = t.grant_id
        WHERE g.created_by = ? AND g.owner != ?)`, nowUTC(), owner, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM guest_grant WHERE created_by = ? AND owner != ?`, owner, owner); err != nil {
		return err
	}
	// Their OWN account's log goes with the account.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM account_log WHERE owner = ?`, owner); err != nil {
		return err
	}
	// Elsewhere, de-identify rather than delete — the same treatment overrides get
	// just below, and for the same reason. This used to be
	// `DELETE ... WHERE actor = ? OR target = ?`, which reached into OTHER households'
	// logs: a row recording something they did on that account, or a guest pass whose
	// sole recipient was this address, was removed outright. That is another
	// household's record of their own actions, and erasing it leaves an unexplained
	// gap in an audit trail they rely on. redactLogTargets (called shortly after)
	// handles the multi-recipient target lists the same way.
	if _, err := tx.ExecContext(ctx,
		`UPDATE account_log SET actor = 'a former member' WHERE owner != ? AND actor = ?`,
		owner, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE account_log SET target = 'a former member' WHERE owner != ? AND target = ?`,
		owner, owner); err != nil {
		return err
	}
	// De-identify bookings they made on another household's permits. The booking
	// itself is that household's live schedule state and must stay.
	if _, err := tx.ExecContext(ctx,
		`UPDATE override SET created_by = 'a former member' WHERE created_by = ? OR created_by = ?`,
		owner, owner+" (undo)"); err != nil {
		return err
	}
	// Anything still queued to them anywhere.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM outbox WHERE status = 'pending' AND recipients = ?`, owner); err != nil {
		return err
	}
	// Their address as the driver contact on ANOTHER household's car. Nothing about
	// this belongs to that household — it is purely a way to reach this person — so
	// deleting it is both correct and exactly what they asked for: no more
	// "your car was bumped off the permit" mail from someone else's account.
	if _, err := tx.ExecContext(ctx,
		`UPDATE vehicle SET email = '' WHERE email = ? AND owner != ?`, owner, owner); err != nil {
		return err
	}
	// Their address on guest passes OTHER households sent TO them. Only the dead
	// ones: a revoked link's recipient is already scheduled to be forgotten after 30
	// days and naming them serves nothing, so this just brings that forward. A LIVE
	// link is deliberately left alone — blanking it would not stop the link working
	// (it is a bearer URL already in their inbox), it would only stop the household
	// that sent it from seeing who to revoke. Deleting your own account should not
	// quietly break someone else's ability to manage their permit.
	if _, err := tx.ExecContext(ctx,
		`UPDATE guest_token SET recipient_email = '' WHERE recipient_email = ? AND revoked_at != ''`,
		owner); err != nil {
		return err
	}
	// Their address inside another household's change log. A guest.create row stores
	// every recipient as one comma-joined string, so the exact-match delete above
	// misses it. Redact rather than delete: the row is that household's record of
	// something THEY did, and erasing it would punch a hole in their audit trail to
	// remove one name from it.
	if err := redactLogTargets(ctx, tx, owner); err != nil {
		return err
	}
	return tx.Commit()
}

// CountLinkedAccounts returns how many accounts currently hold a council session
// cookie — the number of households the service is actively managing permits for.
// Used to enforce the signup cap.
func (s *Store) CountLinkedAccounts(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM council_session WHERE cookie_sealed != ''`).Scan(&n)
	return n, err
}

// ---- Account members (shared access) ----

// AccountMember is a secondary email with access to a primary's account.
type AccountMember struct {
	Email   string
	AddedAt time.Time
	// Pending means the invited person has not accepted yet, so this row grants no
	// access at all. See MemberAccount.
	Pending bool
}

// MemberAccount returns the primary account owner that memberEmail is a secondary
// of, or ok=false when they are their own account.
//
// A PENDING invite is not a membership: it is one person's proposal, and until the
// invited person accepts it must not redirect their data, hide their own account, or
// grant them sight of anyone else's household. This predicate is the single place
// that distinction is enforced, because every caller resolves account scope through
// here.
func (s *Store) MemberAccount(ctx context.Context, memberEmail string) (owner string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT owner FROM account_member WHERE member_email = ? AND invite_pending = 0`, memberEmail).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return owner, true, nil
}

// PendingInvite returns the account that has invited memberEmail but is still
// waiting on them, so the app can offer the choice when they next sign in.
func (s *Store) PendingInvite(ctx context.Context, memberEmail string) (owner string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT owner FROM account_member WHERE member_email = ? AND invite_pending = 1`, memberEmail).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return owner, true, nil
}

// AcceptInvite turns a pending invite into a real membership. Scoped to the owner
// the invitee was actually shown, so a stale form cannot enrol them somewhere else,
// and gated on still being pending so a replayed submit is a no-op rather than a
// second acceptance.
//
// Returns ErrNotFound when there is no such pending invite.
// The prerequisites are checked INSIDE the same statement, not by the caller
// beforehand: a council link or a first vehicle landing between a caller's check and
// this update would accept the invite anyway, leaving a secondary whose own permits and
// session are hidden under someone else's account. Returns ErrInviteBlocked when the
// invitee has become a primary or acquired their own data, so the handler can say which.
func (s *Store) AcceptInvite(ctx context.Context, memberEmail, owner string) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE account_member SET invite_pending = 0, added_at = ?
WHERE member_email = ? AND owner = ? AND invite_pending = 1
  AND NOT EXISTS (SELECT 1 FROM account_member m2 WHERE m2.owner = ?)
  AND NOT EXISTS (SELECT 1 FROM council_session WHERE owner = ?)
  AND NOT EXISTS (SELECT 1 FROM permit WHERE owner = ?)
  AND NOT EXISTS (SELECT 1 FROM vehicle WHERE owner = ?)`,
		nowUTC(), memberEmail, owner, memberEmail, memberEmail, memberEmail, memberEmail)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Either no pending invite, or a prerequisite now fails. Distinguish them so the
		// handler does not tell someone "no such invitation" when the real reason is that
		// they just linked a council account.
		var blocked int
		if e := s.db.QueryRowContext(ctx, `SELECT
        EXISTS(SELECT 1 FROM account_member WHERE owner = ?)
     OR EXISTS(SELECT 1 FROM council_session WHERE owner = ?)
     OR EXISTS(SELECT 1 FROM permit WHERE owner = ?)
     OR EXISTS(SELECT 1 FROM vehicle WHERE owner = ?)`,
			memberEmail, memberEmail, memberEmail, memberEmail).Scan(&blocked); e == nil && blocked == 1 {
			return ErrInviteBlocked
		}
		return ErrNotFound
	}
	return nil
}

// ErrInviteBlocked means the invitee cannot become a secondary: they now run their own
// account (own data) or are a primary with dependants of their own.
var ErrInviteBlocked = errors.New("store: invitee has their own account data or dependants")

// DeclineInvite removes a pending invite. Deliberately restricted to pending rows:
// this is the invitee's own refusal, not a way to leave an account they have already
// joined (that is RemoveMembership, which also cleans up their prefs and passes).
func (s *Store) DeclineInvite(ctx context.Context, memberEmail string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM account_member WHERE member_email = ? AND invite_pending = 1`, memberEmail)
	return err
}

// AccountEmails returns every email that should be notified for an account: the
// owner plus any ACCEPTED secondaries. Always includes the owner, even if listing
// the secondaries fails.
//
// Pending invitees are excluded deliberately. ListMembers includes them so the owner
// can see an unanswered invite, but someone who has not accepted is not part of the
// household: mailing them a permit's activity would disclose that household's
// movements to a person who never agreed to anything, on the say-so of whoever typed
// their address.
func (s *Store) AccountEmails(ctx context.Context, owner string) ([]string, error) {
	emails := []string{owner}
	ms, err := s.ListMembers(ctx, owner)
	if err != nil {
		return emails, err
	}
	for _, m := range ms {
		if m.Pending {
			continue
		}
		emails = append(emails, m.Email)
	}
	return emails, nil
}

// AdminAccount is a per-owner operational summary for the admin dashboard and the
// machine-readable status endpoint the outage watchdog polls.
type AdminAccount struct {
	Owner           string
	MemberOf        string    // non-empty: this owner is a secondary on another account
	Linked          bool      // has a stored council session cookie
	LinkedAt        time.Time // last interactive link
	LastActive      time.Time // last time anyone on the account used the app: the re-authorise clock
	WarmedAt        time.Time // last keep-warm / refresh (council_session.updated_at)
	TokenExpiry     time.Time
	EmailEnabled    bool
	NtfyEnabled     bool
	NtfyTopic       string
	ConsentVersion  string
	PermitCount     int
	MemberCount     int
	Plates          []string // active plate on each managed permit
	LastApplyAt     time.Time
	LastApplyStatus string // status of the most recent apply_log row for the account
	MaxFailStreak   int    // highest live consecutive-failure count across the owner's permits (0 = nothing failing now)
}

// AdminAccounts returns an operational summary for every known account (anyone who
// has consented, linked the council, holds a permit, or set notify prefs), newest
// council activity aside. It is read-only and owner-agnostic — callers must gate it
// to admins.
func (s *Store) AdminAccounts(ctx context.Context) ([]AdminAccount, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT o.owner,
  COALESCE((SELECT owner FROM account_member WHERE member_email = o.owner LIMIT 1), ''),
  COALESCE(cs.cookie_sealed, ''), COALESCE(cs.linked_at, ''), COALESCE(cs.last_active_at, ''), COALESCE(cs.updated_at, ''), COALESCE(cs.token_expiry, ''),
  COALESCE(np.email_enabled, 1), COALESCE(np.ntfy_enabled, 0), COALESCE(np.ntfy_topic, ''),
  COALESCE((SELECT version FROM consent c WHERE c.owner = o.owner ORDER BY id DESC LIMIT 1), ''),
  (SELECT COUNT(*) FROM permit p WHERE p.owner = o.owner),
  (SELECT COUNT(*) FROM account_member m WHERE m.owner = o.owner),
  COALESCE((SELECT al.status FROM apply_log al JOIN permit p ON p.id = al.permit_id WHERE p.owner = o.owner ORDER BY al.id DESC LIMIT 1), ''),
  COALESCE((SELECT al.at     FROM apply_log al JOIN permit p ON p.id = al.permit_id WHERE p.owner = o.owner ORDER BY al.id DESC LIMIT 1), ''),
  (SELECT COALESCE(MAX(fail_streak), 0) FROM permit p WHERE p.owner = o.owner)
FROM (
  SELECT owner FROM council_session
  UNION SELECT owner FROM permit
  UNION SELECT owner FROM consent
  UNION SELECT owner FROM notify_pref
) o
LEFT JOIN council_session cs ON cs.owner = o.owner
LEFT JOIN notify_pref np ON np.owner = o.owner
ORDER BY o.owner`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminAccount
	// Indexes into out, not pointers: append may reallocate the backing array,
	// which would leave earlier pointers writing into the abandoned copy.
	byOwner := map[string]int{}
	for rows.Next() {
		var a AdminAccount
		var cookie, linked, active, warmed, expiry, lastAt string
		var emailEn, ntfyEn int
		if err := rows.Scan(&a.Owner, &a.MemberOf, &cookie, &linked, &active, &warmed, &expiry,
			&emailEn, &ntfyEn, &a.NtfyTopic, &a.ConsentVersion, &a.PermitCount, &a.MemberCount,
			&a.LastApplyStatus, &lastAt, &a.MaxFailStreak); err != nil {
			return nil, err
		}
		a.Linked = cookie != ""
		a.EmailEnabled = emailEn == 1
		a.NtfyEnabled = ntfyEn == 1
		a.LinkedAt, _ = time.Parse(time.RFC3339, linked)
		a.LastActive, _ = time.Parse(time.RFC3339, active)
		a.WarmedAt, _ = time.Parse(time.RFC3339, warmed)
		a.TokenExpiry, _ = time.Parse(time.RFC3339, expiry)
		a.LastApplyAt, _ = time.Parse(time.RFC3339, lastAt)
		out = append(out, a)
		byOwner[a.Owner] = len(out) - 1
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Fold in each account's active plates in a single extra query.
	prows, err := s.db.QueryContext(ctx,
		`SELECT owner, active_registration FROM permit WHERE active_registration != '' ORDER BY owner, id`)
	if err != nil {
		return nil, err
	}
	defer prows.Close()
	for prows.Next() {
		var owner, reg string
		if err := prows.Scan(&owner, &reg); err != nil {
			return nil, err
		}
		if i, ok := byOwner[owner]; ok {
			out[i].Plates = append(out[i].Plates, reg)
		}
	}
	return out, prows.Err()
}

// RosterEntry is one account's outage-notification contact.
type RosterEntry struct {
	Email string `json:"email"`
	Ntfy  string `json:"ntfy,omitempty"` // topic, only when ntfy is enabled
}

// NotifyRoster returns the contact list an outage watchdog would use: every
// consented account, with its ntfy topic when enabled. Email is the baseline
// channel, so it is always the account email.
func (s *Store) NotifyRoster(ctx context.Context) ([]RosterEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT c.owner,
  CASE WHEN COALESCE(np.ntfy_enabled,0)=1 THEN COALESCE(np.ntfy_topic,'') ELSE '' END
FROM (SELECT DISTINCT owner FROM consent) c
LEFT JOIN notify_pref np ON np.owner = c.owner
ORDER BY c.owner`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RosterEntry
	for rows.Next() {
		var e RosterEntry
		if err := rows.Scan(&e.Email, &e.Ntfy); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListMembers returns the secondaries with access to owner's account, oldest first.
// ListMembers returns the account's secondaries INCLUDING those still awaiting
// acceptance, flagged as such. The owner needs to see an outstanding invite —
// otherwise "I added them and nothing happened" is indistinguishable from a lost
// email — but every access decision keys off Pending, never off mere presence here.
func (s *Store) ListMembers(ctx context.Context, owner string) ([]AccountMember, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT member_email, added_at, invite_pending FROM account_member WHERE owner = ? ORDER BY added_at`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccountMember
	for rows.Next() {
		var m AccountMember
		var at string
		var pending int
		if err := rows.Scan(&m.Email, &at, &pending); err != nil {
			return nil, err
		}
		m.AddedAt, _ = time.Parse(time.RFC3339, at)
		m.Pending = pending != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

// CountMembers returns how many secondaries owner's account already has.
func (s *Store) CountMembers(ctx context.Context, owner string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM account_member WHERE owner = ?`, owner).Scan(&n)
	return n, err
}

// AddMember grants memberEmail access to owner's account. It fails if memberEmail
// already has access somewhere (member_email is unique); callers enforce the
// per-account cap and the not-self / not-a-primary checks.
func (s *Store) AddMember(ctx context.Context, owner, memberEmail string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO account_member (member_email, owner, added_at) VALUES (?, ?, ?)`,
		memberEmail, owner, nowUTC())
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	return err
}

// ErrMemberLimit means the account already has the maximum number of secondaries.
var ErrMemberLimit = errors.New("store: shared-access member limit reached")

// AddMemberCapped adds a secondary only if the account is below max, atomically:
// the count check and insert are one statement, so concurrent adds can't slip
// past the cap. Returns ErrMemberLimit when full, or the underlying error (e.g. a
// unique-constraint violation when the email is already a member somewhere).
// The invite starts PENDING: it is an offer, not a membership, and grants nothing
// until the invited person accepts. Pending invites still count toward the cap, so
// one account cannot hold open an unlimited number of outstanding offers — each one
// is an email somebody else has to deal with.
func (s *Store) AddMemberCapped(ctx context.Context, owner, memberEmail string, max int) error {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO account_member (member_email, owner, added_at, invite_pending)
SELECT ?, ?, ?, 1
WHERE (SELECT COUNT(1) FROM account_member WHERE owner = ?) < ?`,
		memberEmail, owner, nowUTC(), owner, max)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrMemberLimit
	}
	return nil
}

// RemoveMember withdraws a person's relationship to this owner's account, scoped to
// the owner so one account cannot reach into another's. It handles BOTH kinds of row
// and is careful to keep them apart:
//
//   - An ACTIVE member (invite_pending = 0) held real access, so their per-person
//     notification prefs, queued mail and any guest passes they minted are torn down,
//     and wasActive is returned true so the caller revokes their sessions.
//   - A PENDING invite (invite_pending = 1) granted NOTHING. The row belongs to this
//     owner, but the address's notify_pref, queued mail and sessions belong to that
//     person's OWN account — a mere offer must never destroy them. Withdrawing one
//     deletes only the invite row and touches nothing else (wasActive = false).
//
// This asymmetry is the load-bearing gate: the teardown below deletes rows keyed by
// the EMAIL alone (a person only ever has one notify_pref / one mailbox), so running
// it for a pending invite would let any user wipe an unrelated stranger's notification
// config, swallow their queued mail and force-revoke their sessions just by inviting
// then "removing" their address. So the invite_pending check, not the membership
// delete, is what guards the teardown.
func (s *Store) RemoveMember(ctx context.Context, owner, memberEmail string) (revokedPasses int64, wasActive bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	var pending int
	err = tx.QueryRowContext(ctx,
		`SELECT invite_pending FROM account_member WHERE member_email = ? AND owner = ?`,
		memberEmail, owner).Scan(&pending)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, ErrNotFound
	}
	if err != nil {
		return 0, false, err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM account_member WHERE member_email = ? AND owner = ?`, memberEmail, owner); err != nil {
		return 0, false, err
	}
	if pending == 1 {
		// A withdrawn offer. Nothing else is scoped to it — commit the single delete and
		// return wasActive=false so the handler does not revoke the stranger's sessions.
		return 0, false, tx.Commit()
	}
	// An active member losing access. Their personal notification prefs go with it —
	// but read the push topic out FIRST, because queued messages already carry it and
	// dropping the row would lose the only handle we have on them.
	if err := dropQueuedPush(ctx, tx, memberEmail); err != nil {
		return 0, false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM notify_pref WHERE owner = ?`, memberEmail); err != nil {
		return 0, false, err
	}
	n, err := revokeGrantsBy(ctx, tx, owner, memberEmail)
	if err != nil {
		return 0, false, err
	}
	return n, true, tx.Commit()
}

// RemoveMembership lets a secondary leave whatever account they belong to.
func (s *Store) RemoveMembership(ctx context.Context, memberEmail string) (revokedPasses int64, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	// Resolve the account first: the grants to revoke are scoped to it, and the
	// membership row is about to go.
	var owner string
	err = tx.QueryRowContext(ctx,
		`SELECT owner FROM account_member WHERE member_email = ?`, memberEmail).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil // not a member of anything; nothing to do
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM account_member WHERE member_email = ?`, memberEmail); err != nil {
		return 0, err
	}
	// Before the prefs row goes: it holds the only copy of their push topic.
	if err := dropQueuedPush(ctx, tx, memberEmail); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM notify_pref WHERE owner = ?`, memberEmail); err != nil {
		return 0, err
	}
	n, err := revokeGrantsBy(ctx, tx, owner, memberEmail)
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// redactLogTargets removes one address from the comma-joined recipient lists in
// other accounts' change-log rows, leaving the rest of each row intact.
//
// Done in Go rather than SQL string surgery because the match has to be on whole
// list ELEMENTS: a LIKE '%addr%' rewrite would also mangle "xa@b.com" when asked
// to remove "a@b.com". The LIKE below is only a prefilter to keep the scan small;
// the real comparison is the exact element match in the loop.
func redactLogTargets(ctx context.Context, tx *sql.Tx, addr string) error {
	if addr == "" {
		return nil
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT id, target FROM account_log WHERE owner != ? AND target LIKE '%' || ? || '%'`, addr, addr)
	if err != nil {
		return err
	}
	type edit struct {
		id     int64
		target string
	}
	var edits []edit
	for rows.Next() {
		var e edit
		if err := rows.Scan(&e.id, &e.target); err != nil {
			rows.Close()
			return err
		}
		parts := strings.Split(e.target, ", ")
		kept := parts[:0]
		for _, p := range parts {
			if !strings.EqualFold(strings.TrimSpace(p), addr) {
				kept = append(kept, p)
			}
		}
		if len(kept) == len(parts) {
			continue // prefilter matched a substring, not a whole address
		}
		e.target = strings.Join(kept, ", ")
		edits = append(edits, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, e := range edits {
		if _, err := tx.ExecContext(ctx,
			`UPDATE account_log SET target = ? WHERE id = ?`, e.target, e.id); err != nil {
			return err
		}
	}
	return nil
}

// dropQueuedPush deletes pending PUSH messages addressed to a departing member's
// own ntfy topic.
//
// Notification preferences are per-person, so each member has their own topic,
// and a queued push carries that topic with an EMPTY recipients column. The
// queued-email purge matches on recipients, so it never touched these: a
// quiet-hours-deferred notice (deferred up to eight hours by default) would still
// push the household's plates and permit label to someone who had just lost
// access. Same failure the email purge was written to prevent, on the other
// channel.
//
// Must run BEFORE the member's notify_pref row is deleted — that row holds the
// only copy of the topic.
func dropQueuedPush(ctx context.Context, tx *sql.Tx, memberEmail string) error {
	var topic string
	err := tx.QueryRowContext(ctx,
		`SELECT ntfy_topic FROM notify_pref WHERE owner = ?`, memberEmail).Scan(&topic)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // never set any preferences; nothing queued to a topic
	}
	if err != nil {
		return err
	}
	if topic == "" {
		return nil
	}
	_, err = tx.ExecContext(ctx,
		`DELETE FROM outbox WHERE status = 'pending' AND ntfy_topic = ?`, topic)
	return err
}

// revokeGrantsBy deletes the guest passes and door QRs a departing member minted,
// in the same transaction as their removal.
//
// This is the whole point of guest_grant.created_by. A pass is a BEARER
// capability: whoever holds the link can put a car on the permit, and a printed
// door QR is a permanent anonymous channel into the account's notifications.
// Without this cascade, "remove their access" removed only their ability to sign
// in — anyone who had copied a raw link (or kept a printed poster) retained
// working access indefinitely, and the account holder had no way to know which
// row to delete. Deleting the grant cascades its tokens, vehicle joins and
// pending requests via foreign keys.
//
// Scoped to the departing member: the primary's own passes, and legacy rows with
// an empty created_by, are deliberately left alone — removing a housemate must
// not silently break the family's own links.
func revokeGrantsBy(ctx context.Context, tx *sql.Tx, owner, memberEmail string) (int64, error) {
	if memberEmail == "" {
		return 0, nil
	}
	// Sweep the live overrides these grants created BEFORE deleting them. override
	// carries guest_token_id with no foreign key, so once the token rows are gone
	// nothing can match those overrides again — they become orphans that still steer
	// the permit (ListOverrides does not join guest_token) and that no later control
	// can remove: revoke, delete-pass and even the account-wide pause all match via a
	// JOIN onto guest_token. The household would be told the car was taken off while a
	// departed member's visitor kept the permit for up to ~2 days. DeleteGuestGrant
	// already sweeps first for exactly this reason.
	if _, err := tx.ExecContext(ctx, sweepLiveGuestOverrides+`IN (
        SELECT t.id FROM guest_token t JOIN guest_grant g ON g.id = t.grant_id
        WHERE g.owner = ? AND g.created_by = ?)`, nowUTC(), owner, memberEmail); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx,
		`DELETE FROM guest_grant WHERE owner = ? AND created_by = ?`, owner, memberEmail)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	// Anything still queued to them goes too. A quiet-hours-deferred notice can sit
	// for hours, so without this someone who just lost access still receives the
	// household's plates and permit label (often their address) by email.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM outbox WHERE status = 'pending' AND recipients = ?`, memberEmail); err != nil {
		return n, err
	}
	return n, nil
}

// IsPrimary reports whether owner is a primary of any shared account (has at
// least one secondary). Used to stop a primary being added as someone's
// secondary while people still depend on their account.
func (s *Store) IsPrimary(ctx context.Context, owner string) (bool, error) {
	n, err := s.CountMembers(ctx, owner)
	return n > 0, err
}

// HasOwnData reports whether email already runs their own p.stonn account, i.e.
// has a linked council session, a managed permit, or a saved vehicle. Adding
// such a person as a secondary would hide their own setup, so the caller blocks
// it. A brand-new user who has only signed in (no data yet) returns false.
func (s *Store) HasOwnData(ctx context.Context, email string) (bool, error) {
	var has int
	err := s.db.QueryRowContext(ctx, `SELECT
        EXISTS(SELECT 1 FROM council_session WHERE owner = ?)
     OR EXISTS(SELECT 1 FROM permit WHERE owner = ?)
     OR EXISTS(SELECT 1 FROM vehicle WHERE owner = ?)`,
		email, email, email).Scan(&has)
	return has == 1, err
}
