package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// CreateQRGrant creates an ephemeral "on-screen QR" grant for a permit: it allows
// a visitor to type an arbitrary plate, has no saved cars or email recipients,
// and its single token expires after ttl. It is hidden from the pass list. Expired
// on-screen grants for the owner are pruned first so they do not accumulate.
// Returns the token hash to store (caller keeps the raw token for the QR URL).
func (s *Store) CreateQRGrant(ctx context.Context, owner, createdBy string, permitID int64, tokenHash, tokenSealed string, ttl time.Duration) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var permitOK int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM permit WHERE id = ? AND owner = ?)`, permitID, owner).Scan(&permitOK); err != nil {
		return 0, err
	}
	if permitOK == 0 {
		return 0, ErrNotFound
	}
	// Retire the owner's already-expired on-screen grants before opening a new one.
	//
	// A visitor QR token lasts 15 minutes; the booking it creates runs to the end of
	// the day. So an expired grant routinely still has a live booking behind it — a
	// 6pm scan good until midnight — and re-opening the QR for the next guest must not
	// cancel it. Sweeping here did exactly that: it took a valid car off the permit
	// hours early, owner-wide, for an action the resident sees as "show a new code".
	//
	// Deleting is no better, because override.guest_token_id has no foreign key: the
	// booking would survive as an orphan that no revocation could ever match. So split
	// the two cases. A grant with nothing live behind it is deleted outright; one that
	// still backs a booking is DISABLED instead, which stops the stale link resolving
	// (activation requires enabled = 1) while leaving the row that the revocation
	// sweeps join through. The household keeps control of the plate; the guest keeps
	// the day they were promised.
	const expiredOnScreen = `SELECT g.id FROM guest_grant g
        WHERE g.owner = ? AND g.on_screen = 1
          AND EXISTS (SELECT 1 FROM guest_token t
                      WHERE t.grant_id = g.id AND t.expires_at != '' AND t.expires_at <= ?)`
	const backsLiveOverride = `EXISTS (SELECT 1 FROM override o
        JOIN guest_token t2 ON t2.id = o.guest_token_id
        WHERE t2.grant_id = guest_grant.id
          AND o.guest_token_id != 0
          AND (o.ends_at IS NULL OR o.ends_at = '' OR o.ends_at > ?))`
	if _, err := tx.ExecContext(ctx,
		`UPDATE guest_grant SET enabled = 0 WHERE id IN (`+expiredOnScreen+`) AND `+backsLiveOverride,
		owner, nowUTC(), nowUTC()); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM guest_grant WHERE id IN (`+expiredOnScreen+`) AND NOT `+backsLiveOverride,
		owner, nowUTC(), nowUTC()); err != nil {
		return 0, err
	}
	// Retiring a grant must also close its pending requests. They used to cascade away
	// with the deleted row; a disabled grant keeps them, and they can never be approved
	// (createOverrideGuarded requires enabled = 1), so the household would get an error
	// on every attempt and the visitor would wait on a decision that cannot arrive.
	if _, err := tx.ExecContext(ctx,
		`UPDATE guest_request SET status = 'denied', decided_at = ?, decided_by = ''
		 WHERE status = 'pending' AND grant_id IN (SELECT id FROM guest_grant WHERE enabled = 0 AND owner = ? AND on_screen = 1)`,
		nowUTC(), owner); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO guest_grant (owner, permit_id, label, allow_overnight, allow_plate, on_screen, enabled, created_at, created_by)
		 VALUES (?, ?, 'Visitor QR', 0, 1, 1, 1, ?, ?)`,
		owner, permitID, nowUTC(), createdBy)
	if err != nil {
		return 0, err
	}
	grantID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	expires := time.Now().UTC().Add(ttl).Format(time.RFC3339)
	// The raw token is kept (sealed) so the SAME code can be shown again while it is
	// still live — see LiveQRGrant. Without it, re-opening the QR would have to mint
	// a second token, leaving two working codes for one doorstep and a stated
	// stop-working time that describes only the newer one. The exposure is much
	// smaller than the printed QR's, which is sealed indefinitely: this one is
	// deleted as soon as it lapses.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO guest_token (grant_id, recipient_email, token_hash, token_sealed, expires_at, created_at)
		 VALUES (?, '', ?, ?, ?, ?)`,
		grantID, tokenHash, tokenSealed, expires, nowUTC()); err != nil {
		return 0, err
	}
	return grantID, tx.Commit()
}

// LiveQRGrant returns the permit's on-screen visitor QR if one is still working,
// so re-opening it shows the SAME code rather than minting another.
//
// This is what makes the button safe to put somewhere prominent. A resident whose
// visitor fumbles the scan will tap again; without reuse that mints a second live
// token, and the first stays valid until its own expiry — two working codes for one
// visitor, and a "stops working at" time that is true of only one of them. Reuse
// also keeps an in-progress scan working instead of racing it.
func (s *Store) LiveQRGrant(ctx context.Context, owner string, permitID int64, now time.Time) (tokenSealed string, expiresAt time.Time, err error) {
	var exp string
	err = s.db.QueryRowContext(ctx, `
SELECT t.token_sealed, t.expires_at
FROM guest_grant g JOIN guest_token t ON t.grant_id = g.id
WHERE g.owner = ? AND g.permit_id = ? AND g.on_screen = 1 AND g.enabled = 1
  AND t.revoked_at = '' AND t.token_sealed != ''
  AND t.expires_at != '' AND t.expires_at > ?
ORDER BY t.id DESC LIMIT 1`,
		owner, permitID, now.UTC().Format(time.RFC3339)).Scan(&tokenSealed, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, ErrNotFound
	}
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt, _ = time.Parse(time.RFC3339, exp)
	return tokenSealed, expiresAt, nil
}

// PrintedGrant is a durable door-QR pass: one per permit, reprintable because its
// token is kept (sealed) so the SAME code can be shown again. TokenSealed is the
// raw token encrypted at rest; the caller opens it to rebuild the activation URL.
type PrintedGrant struct {
	GrantID     int64
	PermitID    int64
	PermitLabel string
	TokenSealed string
	CreatedAt   time.Time
}

// CreatePrintedGrant mints (or replaces) the printed door QR for a permit: it drops
// any existing printed grant for that permit and inserts a fresh one. tokenSealed is
// the raw token encrypted at rest so the same code can be reprinted later; tokenHash
// is the lookup key used when a visitor scans.
func (s *Store) CreatePrintedGrant(ctx context.Context, owner, createdBy string, permitID int64, tokenHash, tokenSealed string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var permitOK int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM permit WHERE id = ? AND owner = ?)`, permitID, owner).Scan(&permitOK); err != nil {
		return 0, err
	}
	if permitOK == 0 {
		return 0, ErrNotFound
	}
	// Replacing the printed QR retires the old code. It does not withdraw approvals the
	// household already gave: those visitors were told their car was on for the day, and
	// printing a fresh poster is not a decision to take it off. RevokePrintedGrant is
	// the control that does that, and it says so.
	//
	// So retire the old grants the same way as the on-screen ones: disable any that
	// still back a live booking (the retired code stops resolving, but the token rows
	// the revocation sweeps join through survive, since override.guest_token_id has no
	// foreign key), and delete the rest.
	const oldPrinted = `SELECT id FROM guest_grant WHERE owner = ? AND permit_id = ? AND request_only = 1`
	const printedBacksLive = `EXISTS (SELECT 1 FROM override o
        JOIN guest_token t2 ON t2.id = o.guest_token_id
        WHERE t2.grant_id = guest_grant.id
          AND o.guest_token_id != 0
          AND (o.ends_at IS NULL OR o.ends_at = '' OR o.ends_at > ?))`
	if _, err := tx.ExecContext(ctx,
		`UPDATE guest_grant SET enabled = 0 WHERE id IN (`+oldPrinted+`) AND `+printedBacksLive,
		owner, permitID, nowUTC()); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM guest_grant WHERE id IN (`+oldPrinted+`) AND NOT `+printedBacksLive,
		owner, permitID, nowUTC()); err != nil {
		return 0, err
	}
	// Retiring a grant must also close its pending requests. They used to cascade away
	// with the deleted row; a disabled grant keeps them, and they can never be approved
	// (createOverrideGuarded requires enabled = 1), so the household would get an error
	// on every attempt and the visitor would wait on a decision that cannot arrive.
	if _, err := tx.ExecContext(ctx,
		`UPDATE guest_request SET status = 'denied', decided_at = ?, decided_by = ''
		 WHERE status = 'pending' AND grant_id IN (SELECT id FROM guest_grant WHERE enabled = 0 AND owner = ? AND permit_id = ? AND request_only = 1)`,
		nowUTC(), owner, permitID); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO guest_grant (owner, permit_id, label, allow_overnight, allow_plate, on_screen, request_only, enabled, created_at, created_by)
		 VALUES (?, ?, 'Printed QR', 0, 1, 0, 1, 1, ?, ?)`, owner, permitID, nowUTC(), createdBy)
	if err != nil {
		return 0, err
	}
	grantID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO guest_token (grant_id, recipient_email, token_hash, token_sealed, created_at) VALUES (?, '', ?, ?, ?)`,
		grantID, tokenHash, tokenSealed, nowUTC()); err != nil {
		return 0, err
	}
	return grantID, tx.Commit()
}

// PrintedGrantByID returns a single owner-scoped printed grant (for the reprint /
// poster view), including its sealed token so the URL can be rebuilt.
func (s *Store) PrintedGrantByID(ctx context.Context, owner string, grantID int64) (PrintedGrant, error) {
	var g PrintedGrant
	var created string
	err := s.db.QueryRowContext(ctx, `
SELECT g.id, g.permit_id, COALESCE(p.label, ''), t.token_sealed, g.created_at
FROM guest_grant g
JOIN permit p ON p.id = g.permit_id
JOIN guest_token t ON t.grant_id = g.id
WHERE g.id = ? AND g.owner = ? AND g.request_only = 1 AND g.enabled = 1`, grantID, owner).
		Scan(&g.GrantID, &g.PermitID, &g.PermitLabel, &g.TokenSealed, &created)
	if err == sql.ErrNoRows {
		return PrintedGrant{}, ErrNotFound
	}
	if err != nil {
		return PrintedGrant{}, err
	}
	g.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return g, nil
}

// PrintedGrantForPermit returns the existing door QR for a permit, or ErrNotFound —
// so creating one can be idempotent (reuse rather than rotate the token).
func (s *Store) PrintedGrantForPermit(ctx context.Context, owner string, permitID int64) (PrintedGrant, error) {
	var g PrintedGrant
	var created string
	err := s.db.QueryRowContext(ctx, `
SELECT g.id, g.permit_id, COALESCE(p.label, ''), t.token_sealed, g.created_at
FROM guest_grant g
JOIN permit p ON p.id = g.permit_id
JOIN guest_token t ON t.grant_id = g.id
WHERE g.owner = ? AND g.permit_id = ? AND g.request_only = 1 AND g.enabled = 1
ORDER BY g.id DESC LIMIT 1`, owner, permitID).
		Scan(&g.GrantID, &g.PermitID, &g.PermitLabel, &g.TokenSealed, &created)
	if err == sql.ErrNoRows {
		return PrintedGrant{}, ErrNotFound
	}
	if err != nil {
		return PrintedGrant{}, err
	}
	g.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return g, nil
}

// ListPrintedGrants returns an owner's durable door QRs, newest first, for the
// management list on the Guests page.
func (s *Store) ListPrintedGrants(ctx context.Context, owner string) ([]PrintedGrant, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT g.id, g.permit_id, COALESCE(p.label, ''), t.token_sealed, g.created_at
FROM guest_grant g
JOIN permit p ON p.id = g.permit_id
JOIN guest_token t ON t.grant_id = g.id
WHERE g.owner = ? AND g.request_only = 1 AND g.enabled = 1
ORDER BY g.id DESC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PrintedGrant
	for rows.Next() {
		var g PrintedGrant
		var created string
		if err := rows.Scan(&g.GrantID, &g.PermitID, &g.PermitLabel, &g.TokenSealed, &created); err != nil {
			return nil, err
		}
		g.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokePrintedGrant deletes an owner's door QR (cascading its token and any pending
// requests), retiring the printed code for good, and sweeps the still-live overrides
// its approvals created — a poster taken down must also take its visitors' plates
// off the permit, which is what the household is told has happened.
func (s *Store) RevokePrintedGrant(ctx context.Context, owner string, grantID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Scoped to every printed grant on this PERMIT, not just the id passed in.
	// Replacing a poster now leaves the superseded grant behind (disabled) whenever it
	// still backs a booking, and the household's UI only ever shows them the current
	// one — so revoking by id alone would leave those earlier visitors' plates on the
	// permit with no control that can reach them. Taking the poster down means all of
	// it, which is what the household is told has happened.
	const printedOnPermit = `SELECT g2.id FROM guest_grant g2
        WHERE g2.owner = ? AND g2.request_only = 1
          AND g2.permit_id = (SELECT permit_id FROM guest_grant WHERE id = ? AND owner = ? AND request_only = 1)`
	if _, err := tx.ExecContext(ctx,
		sweepLiveGuestOverrides+`IN (SELECT t.id FROM guest_token t WHERE t.grant_id IN (`+printedOnPermit+`))`,
		nowUTC(), owner, grantID, owner); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx,
		`DELETE FROM guest_grant WHERE id IN (`+printedOnPermit+`)`, owner, grantID, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}
