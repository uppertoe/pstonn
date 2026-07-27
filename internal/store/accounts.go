package store

import (
	"context"
	"database/sql"
	"errors"
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
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM guest_grant WHERE created_by = ? AND owner != ?`, owner, owner); err != nil {
		return err
	}
	// Their change-log entries elsewhere (as the actor, or named as the target of a
	// member add/remove).
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM account_log WHERE actor = ? OR target = ?`, owner, owner); err != nil {
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
}

// MemberAccount returns the primary account owner that memberEmail is a secondary
// of, or ok=false when they are their own account.
func (s *Store) MemberAccount(ctx context.Context, memberEmail string) (owner string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT owner FROM account_member WHERE member_email = ?`, memberEmail).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return owner, true, nil
}

// AccountEmails returns every email that should be notified for an account: the
// owner plus any secondaries. Always includes the owner, even if listing the
// secondaries fails.
func (s *Store) AccountEmails(ctx context.Context, owner string) ([]string, error) {
	emails := []string{owner}
	ms, err := s.ListMembers(ctx, owner)
	if err != nil {
		return emails, err
	}
	for _, m := range ms {
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
	LinkedAt        time.Time // last interactive link (the re-authorise clock start)
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
}

// AdminAccounts returns an operational summary for every known account (anyone who
// has consented, linked the council, holds a permit, or set notify prefs), newest
// council activity aside. It is read-only and owner-agnostic — callers must gate it
// to admins.
func (s *Store) AdminAccounts(ctx context.Context) ([]AdminAccount, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT o.owner,
  COALESCE((SELECT owner FROM account_member WHERE member_email = o.owner LIMIT 1), ''),
  COALESCE(cs.cookie_sealed, ''), COALESCE(cs.linked_at, ''), COALESCE(cs.updated_at, ''), COALESCE(cs.token_expiry, ''),
  COALESCE(np.email_enabled, 1), COALESCE(np.ntfy_enabled, 0), COALESCE(np.ntfy_topic, ''),
  COALESCE((SELECT version FROM consent c WHERE c.owner = o.owner ORDER BY id DESC LIMIT 1), ''),
  (SELECT COUNT(*) FROM permit p WHERE p.owner = o.owner),
  (SELECT COUNT(*) FROM account_member m WHERE m.owner = o.owner),
  COALESCE((SELECT al.status FROM apply_log al JOIN permit p ON p.id = al.permit_id WHERE p.owner = o.owner ORDER BY al.id DESC LIMIT 1), ''),
  COALESCE((SELECT al.at     FROM apply_log al JOIN permit p ON p.id = al.permit_id WHERE p.owner = o.owner ORDER BY al.id DESC LIMIT 1), '')
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
		var cookie, linked, warmed, expiry, lastAt string
		var emailEn, ntfyEn int
		if err := rows.Scan(&a.Owner, &a.MemberOf, &cookie, &linked, &warmed, &expiry,
			&emailEn, &ntfyEn, &a.NtfyTopic, &a.ConsentVersion, &a.PermitCount, &a.MemberCount,
			&a.LastApplyStatus, &lastAt); err != nil {
			return nil, err
		}
		a.Linked = cookie != ""
		a.EmailEnabled = emailEn == 1
		a.NtfyEnabled = ntfyEn == 1
		a.LinkedAt, _ = time.Parse(time.RFC3339, linked)
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
func (s *Store) ListMembers(ctx context.Context, owner string) ([]AccountMember, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT member_email, added_at FROM account_member WHERE owner = ? ORDER BY added_at`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccountMember
	for rows.Next() {
		var m AccountMember
		var at string
		if err := rows.Scan(&m.Email, &at); err != nil {
			return nil, err
		}
		m.AddedAt, _ = time.Parse(time.RFC3339, at)
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
func (s *Store) AddMemberCapped(ctx context.Context, owner, memberEmail string, max int) error {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO account_member (member_email, owner, added_at)
SELECT ?, ?, ?
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

// RemoveMember revokes a secondary's access, scoped to the owner so one account
// cannot remove another's member.
func (s *Store) RemoveMember(ctx context.Context, owner, memberEmail string) (revokedPasses int64, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM account_member WHERE member_email = ? AND owner = ?`, memberEmail, owner); err != nil {
		return 0, err
	}
	// Their personal notification prefs go with their access.
	if _, err := tx.ExecContext(ctx, `DELETE FROM notify_pref WHERE owner = ?`, memberEmail); err != nil {
		return 0, err
	}
	n, err := revokeGrantsBy(ctx, tx, owner, memberEmail)
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
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
	if _, err := tx.ExecContext(ctx, `DELETE FROM notify_pref WHERE owner = ?`, memberEmail); err != nil {
		return 0, err
	}
	n, err := revokeGrantsBy(ctx, tx, owner, memberEmail)
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
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
