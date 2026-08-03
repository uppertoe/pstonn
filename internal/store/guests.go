package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
)

// ---- Guest passes ----

// GuestGrant is a link-based permission the account holder creates: it lets a
// non-account recipient put one of a permitted set of the account's cars onto a
// permit. Tokens (one per recipient) live in guest_token.
type GuestGrant struct {
	ID             int64
	Owner          string
	PermitID       int64
	Label          string
	AllowOvernight bool
	AllowPlate     bool // visitor may type an arbitrary plate (tradie / on-screen QR)
	RequestOnly    bool // printed QR: a scan only requests; the holder approves live
	Enabled        bool
	CreatedAt      time.Time
}

// GuestRequest is a visitor's pending/approved/denied request to use a
// printed-QR permit.
type GuestRequest struct {
	ID          int64
	GrantID     int64
	Owner       string
	PermitID    int64
	Plate       string
	Status      string // pending | approved | denied
	RequestedAt time.Time
	DecidedAt   time.Time // when the holder approved/denied ("" while pending)
	DecidedBy   string    // which account member decided ("" while pending / expired unanswered)
	Until       string    // human "until …" text, set on approval
	UntilTS     time.Time // when the approved window ends (zero while pending/denied)
}

// GuestToken is one recipient's link to a grant; the raw token is never stored,
// only its hash.
type GuestToken struct {
	ID             int64
	GrantID        int64
	RecipientEmail string
	Revoked        bool
	CreatedAt      time.Time
}

// GuestRecipient is a (recipient, token-hash) pair passed to CreateGuestGrant;
// the caller generates the raw token, keeps it to build the link, and hands the
// store only the hash.
type GuestRecipient struct {
	Email     string
	TokenHash string
}

// GuestContext is everything the public activation page needs, resolved from a
// presented token hash. It is only returned when the token is live (not revoked),
// its grant enabled, and the owner's kill-switch on — otherwise ErrNotFound.
type GuestContext struct {
	Grant     GuestGrant
	TokenID   int64
	Recipient string
	Vehicles  []model.Vehicle
	// BaselinePlate is what was on the permit before this link's current run of
	// activations began ('' = unknown), and BaselineUntil is when that run's
	// window ends (zero = no run captured). Together they let the guest revert
	// their changes back to the pre-existing plate.
	BaselinePlate string
	BaselineUntil time.Time
}

// GuestGrantDetail is a grant with its allowed cars and recipient links, for the
// account holder's management UI.
type GuestGrantDetail struct {
	Grant    GuestGrant
	Vehicles []model.Vehicle
	Tokens   []GuestToken
}

// CreateGuestGrant creates a grant, its allowed-vehicle set, and one token per
// recipient, all in a transaction. Every vehicle must belong to owner (IDOR
// guard). Returns the new grant id.
func (s *Store) CreateGuestGrant(ctx context.Context, owner, createdBy string, permitID int64, label string, allowOvernight bool, vehicleIDs []int64, recipients []GuestRecipient) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// The permit must belong to the owner.
	var permitOK int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM permit WHERE id = ? AND owner = ?)`, permitID, owner).Scan(&permitOK); err != nil {
		return 0, err
	}
	if permitOK == 0 {
		return 0, ErrNotFound
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO guest_grant (owner, permit_id, label, allow_overnight, enabled, created_at, created_by) VALUES (?, ?, ?, ?, 1, ?, ?)`,
		owner, permitID, label, boolInt(allowOvernight), nowUTC(), createdBy)
	if err != nil {
		return 0, err
	}
	grantID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for _, vid := range vehicleIDs {
		// Insert only if the vehicle belongs to the owner; a foreign id inserts
		// nothing rather than binding a stranger's car into the grant.
		r, err := tx.ExecContext(ctx,
			`INSERT INTO guest_grant_vehicle (grant_id, vehicle_id)
			 SELECT ?, ? WHERE EXISTS(SELECT 1 FROM vehicle WHERE id = ? AND owner = ?)`,
			grantID, vid, vid, owner)
		if err != nil {
			return 0, err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return 0, ErrNotFound
		}
	}
	for _, rc := range recipients {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO guest_token (grant_id, recipient_email, token_hash, created_at) VALUES (?, ?, ?, ?)`,
			grantID, rc.Email, rc.TokenHash, nowUTC()); err != nil {
			return 0, err
		}
	}
	return grantID, tx.Commit()
}

// UpdateGuestGrant changes a grant's label, overnight policy, and allowed-vehicle
// set (replacing it wholesale), scoped to owner. The permit is not changed — its
// tokens are bound to it. Every vehicle must belong to owner.
//
// Only a real emailed pass may be edited, which is why the on_screen /
// request_only grants are excluded exactly as they are in ResetGuestToken. Those
// two are machine-minted and their tokens are handed out differently: the printed
// door QR is left on a wall for anyone to scan, so attaching household cars to it
// would turn "scan and ask" into "scan and tap the resident's car onto the
// permit", and the ephemeral on-screen grant is not a pass anyone manages. The UI
// never offers either, so an update naming one is a crafted POST.
func (s *Store) UpdateGuestGrant(ctx context.Context, owner string, grantID int64, label string, allowOvernight bool, vehicleIDs []int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`UPDATE guest_grant SET label = ?, allow_overnight = ?
		 WHERE id = ? AND owner = ? AND on_screen = 0 AND request_only = 0`,
		label, boolInt(allowOvernight), grantID, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM guest_grant_vehicle WHERE grant_id = ?`, grantID); err != nil {
		return err
	}
	for _, vid := range vehicleIDs {
		r, err := tx.ExecContext(ctx,
			`INSERT INTO guest_grant_vehicle (grant_id, vehicle_id)
			 SELECT ?, ? WHERE EXISTS(SELECT 1 FROM vehicle WHERE id = ? AND owner = ?)`,
			grantID, vid, vid, owner)
		if err != nil {
			return err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return ErrNotFound
		}
	}
	return tx.Commit()
}

// AddGuestTokens adds recipient tokens to an existing grant (scoped to owner),
// skipping any email that already has a live token on it. Returns the emails
// actually added, so the caller can email and display just those links.
//
// One transaction, deliberately. Two statements per recipient on the single
// shared SQLite connection is fine for the handful of addresses a household
// types, but the recipient list is free text: without a transaction a long list
// interleaves thousands of individually-committed statements with the reconcile
// loop's own queries, and a permit that stops being updated is a parking fine.
// The caller caps the list; this keeps whatever it does pass through cheap and
// all-or-nothing, so a failure halfway cannot leave live tokens the caller never
// learned about (and therefore never emailed a link for).
func (s *Store) AddGuestTokens(ctx context.Context, owner string, grantID int64, recipients []GuestRecipient) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var ok int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM guest_grant WHERE id = ? AND owner = ?)`, grantID, owner).Scan(&ok); err != nil {
		return nil, err
	}
	if ok == 0 {
		return nil, ErrNotFound
	}
	var added []string
	for _, rc := range recipients {
		var live int
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM guest_token WHERE grant_id = ? AND recipient_email = ? AND revoked_at = '')`,
			grantID, rc.Email).Scan(&live); err != nil {
			return nil, err
		}
		if live == 1 {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO guest_token (grant_id, recipient_email, token_hash, created_at) VALUES (?, ?, ?, ?)`,
			grantID, rc.Email, rc.TokenHash, nowUTC()); err != nil {
			return nil, err
		}
		added = append(added, rc.Email)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return added, nil
}

// ResetGuestToken issues a fresh link for one existing recipient of an emailed
// grant: it revokes their current token(s) and inserts a new one with newHash, so
// exactly one link is live per recipient. Used by the "re-send" action — the
// original link can't be re-sent (only its hash is stored), so re-sending
// necessarily supersedes it. Owner-scoped; ErrNotFound if the grant isn't the
// owner's or the recipient was never on it.
func (s *Store) ResetGuestToken(ctx context.Context, owner string, grantID int64, recipientEmail, newHash string) (permitID int64, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx,
		`SELECT permit_id FROM guest_grant WHERE id = ? AND owner = ? AND on_screen = 0 AND request_only = 0`,
		grantID, owner).Scan(&permitID)
	if err == sql.ErrNoRows {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	var wasRecipient int
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM guest_token WHERE grant_id = ? AND recipient_email = ?)`,
		grantID, recipientEmail).Scan(&wasRecipient); err != nil {
		return 0, err
	}
	if wasRecipient == 0 {
		return 0, ErrNotFound
	}
	// Re-issue the link by REBINDING the recipient's existing token row to the new
	// hash rather than replacing the row. The old link dies either way (hash-only
	// storage, and the hash just changed), but the row's id survives — which matters
	// twice over. A booking already made through the old link keeps running: the guest
	// was told their car was on until the end of the day, and a re-send is not a
	// decision to take it off, so deleting the row (or sweeping the override) would
	// pull a valid car off the permit early and hand the visitor a fine. And because
	// override.guest_token_id has no foreign key, keeping the id is also what keeps
	// that booking REACHABLE: every later sweep joins guest_token, so a deleted row
	// would strand the override beyond any revocation.
	//
	// Explicit revocation is the separate, deliberate act — RevokeGuestToken and the
	// account-removal sweep still take the plate off, because there the household has
	// said so and the UI promises exactly that.
	var keepID int64
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM guest_token WHERE grant_id = ? AND recipient_email = ? ORDER BY id DESC LIMIT 1`,
		grantID, recipientEmail).Scan(&keepID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		// baseline_plate / baseline_until are deliberately LEFT ALONE. They hold the
		// plate that was on the permit before this link was used, and "Put <plate> back"
		// promises to restore exactly that. The booking survives a re-send, so its undo
		// must survive too — clearing it both removes the guest's revert and lets the
		// next activation capture the GUEST's plate as the baseline, so a later visitor's
		// "put it back" would restore the wrong car. Stale baselines are already replaced
		// by CaptureOrExtendGuestBaseline once the window lapses.
		`UPDATE guest_token SET token_hash = ?, created_at = ?, revoked_at = '', expires_at = '' WHERE id = ?`,
		newHash, nowUTC(), keepID); err != nil {
		return 0, err
	}
	// Any duplicate rows for this recipient are retired rather than deleted, for the
	// same reachability reason; the recipient still shows exactly once, since the
	// management list reads live tokens.
	if _, err := tx.ExecContext(ctx,
		`UPDATE guest_token SET revoked_at = ? WHERE grant_id = ? AND recipient_email = ? AND id != ? AND revoked_at = ''`,
		nowUTC(), grantID, recipientEmail, keepID); err != nil {
		return 0, err
	}
	return permitID, tx.Commit()
}

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

// CreateGuestRequest records a pending request from a printed-QR scan. nonce is a
// per-request secret the visitor keeps, so they can poll its status without being
// able to read other requests.
// CreateGuestRequest records a pending printed-QR request, or reuses an existing
// still-pending one for the same grant+plate so a double-scan/submit doesn't stack
// duplicate requests (and duplicate approval nudges). Returns the request id, the
// effective nonce (the reused row's, so its status page keeps working), and
// whether a NEW request was created (the caller only notifies when it did).
// ErrGuestRequestLimit means the grant already has the maximum number of open
// pending requests. The door QR is deliberately public, so without a cap anyone
// who has seen the poster could flood the holder's approval queue (and their
// notification channels) with junk plates.
//
// On the reuse path the returned nonce is the EXISTING row's poll secret, and the
// store has no way to tell who is asking. It must therefore only ever be
// disclosed to a requester who can already present it — two different visitors
// can type the same plate, and handing the second one the first one's nonce lets
// them read a stranger's request. guestRequest gates it on the browser's own
// request cookie for exactly this reason.
var ErrGuestRequestLimit = errors.New("store: too many pending requests for this grant")

// maxPendingGuestRequests bounds open pending rows per grant.
const maxPendingGuestRequests = 5

// guestReqReserved is how many of those slots are held back for a scanner the
// request handler has not heard from recently.
//
// The cap alone is a shared resource on a PUBLIC surface: five posts with
// distinct plates fill it from one phone, and because pending rows only age out
// after an hour (on a 15-minute sweep) that bricks the door QR for the next
// visitor for 60-75 minutes, repeatably. Refusing a scanner who has already
// asked once the queue reaches the reserved tail means one phone can occupy at
// most maxPendingGuestRequests-guestReqReserved slots, so a genuine visitor —
// whom we have not heard from — always has somewhere to land. Below the tail
// nobody is throttled at all, so the ordinary case (an empty queue, a visitor
// mistyping their plate twice) is untouched.
const guestReqReserved = 2

// PendingGuestRequestsInReserve reports whether a grant's pending queue has grown
// into the slots reserved for a scanner we have not heard from (see
// guestReqReserved). The handler consults it before creating a request so the
// reserve policy lives next to the cap it partitions.
func (s *Store) PendingGuestRequestsInReserve(ctx context.Context, grantID int64) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM guest_request WHERE grant_id = ? AND status = 'pending'`, grantID).Scan(&n); err != nil {
		return false, err
	}
	return n >= maxPendingGuestRequests-guestReqReserved, nil
}

func (s *Store) CreateGuestRequest(ctx context.Context, grantID, permitID int64, owner, plate, nonce string) (id int64, effNonce string, created bool, err error) {
	// Dedup (same plate re-scan reuses the pending request), the pending cap, and
	// the insert are ONE guarded statement: a separate check-then-insert lets two
	// simultaneous scans both pass the check and double-insert/over-fill.
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO guest_request (grant_id, owner, permit_id, plate, nonce, status, requested_at)
		 SELECT ?1, ?2, ?3, ?4, ?5, 'pending', ?6
		 WHERE NOT EXISTS (SELECT 1 FROM guest_request WHERE grant_id = ?1 AND plate = ?4 AND status = 'pending')
		   AND (SELECT COUNT(*) FROM guest_request WHERE grant_id = ?1 AND status = 'pending') < ?7`,
		grantID, owner, permitID, plate, nonce, nowUTC(), maxPendingGuestRequests)
	if err != nil {
		return 0, "", false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		id, err = res.LastInsertId()
		return id, nonce, true, err
	}
	// The guarded insert declined: either this plate already has a pending
	// request (reuse it) or the grant is at its pending cap.
	var existingID int64
	var existingNonce string
	e := s.db.QueryRowContext(ctx,
		`SELECT id, nonce FROM guest_request WHERE grant_id = ? AND plate = ? AND status = 'pending' ORDER BY id DESC LIMIT 1`,
		grantID, plate).Scan(&existingID, &existingNonce)
	if e == nil {
		return existingID, existingNonce, false, nil
	}
	if e != sql.ErrNoRows {
		return 0, "", false, e
	}
	return 0, "", false, ErrGuestRequestLimit
}

// ExpireGuestRequests marks pending requests older than before as expired, so a
// stale "approve this plate?" can't be actioned days later (approving an old row
// would silently put an unknown plate on today's permit) and abandoned scans
// drain out of the holder's queue. Expired rows read as denied to the visitor.
func (s *Store) ExpireGuestRequests(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE guest_request SET status = 'expired', decided_at = ? WHERE status = 'pending' AND requested_at < ?`,
		nowUTC(), before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ForgetRevokedRecipients clears the email address on guest links that were
// revoked before the cutoff. Once a link is dead the address serves no purpose —
// it cannot be re-sent to and nothing reads it — so holding a third party's
// contact details indefinitely is not justifiable. The row itself stays, so the
// owner can still see that a recipient existed and was revoked.
func (s *Store) ForgetRevokedRecipients(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE guest_token SET recipient_email = ''
WHERE recipient_email != '' AND revoked_at != '' AND revoked_at < ?`,
		before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// settledNonceGrace is how long a denied or expired request keeps its poll secret
// after being decided.
//
// It exists so the visitor can still LEARN the outcome. A denied or expired
// request has no until_ts (no approved run ever started), so a plain "past its
// window" test cleared the nonce on the very next sweep — sometimes in the same
// pass that expired it — and GuestRequestForPoll requires the nonce. The visitor's
// re-scan then resolved to nothing, so the distinct "your request timed out"
// message was unreachable and every unsuccessful outcome looked like a refusal.
// Matched to the 48h re-scan cookie window in the server package: once that cookie
// is gone nobody can present the nonce anyway, so holding it longer buys nothing.
const settledNonceGrace = 48 * time.Hour

// ClearSettledRequestNonces drops the poll secret from printed-QR requests once it
// can no longer tell a visitor anything, so a live capability does not sit in the
// table for the rest of its retention. An approved request keeps its nonce until
// its window ends; a denied or expired one keeps it for settledNonceGrace after
// the decision. Pending requests always keep theirs — the visitor is still polling.
func (s *Store) ClearSettledRequestNonces(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE guest_request SET nonce = ''
WHERE nonce != '' AND status != 'pending'
  AND (
        (until_ts != '' AND until_ts < ?)
     OR (until_ts = '' AND decided_at != '' AND decided_at < ?)
     OR (until_ts = '' AND decided_at = '')
      )`,
		now.UTC().Format(time.RFC3339),
		now.Add(-settledNonceGrace).UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PurgeDecidedGuestRequests deletes non-pending requests older than before.
// Visitor plates are PII; once a request is decided (or expired) there is no
// reason to keep it beyond a short audit window.
func (s *Store) PurgeDecidedGuestRequests(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM guest_request WHERE status != 'pending' AND requested_at < ?`,
		before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GuestRequestForPoll returns a request only if the nonce matches — the visitor's
// status check, safe against request-id enumeration.
func (s *Store) GuestRequestForPoll(ctx context.Context, id int64, nonce string) (GuestRequest, error) {
	return s.scanGuestRequest(s.db.QueryRowContext(ctx,
		`SELECT id, grant_id, owner, permit_id, plate, status, requested_at, decided_at, decided_by, until_at, until_ts
		 FROM guest_request WHERE id = ? AND nonce = ? AND nonce != ''`, id, nonce))
}

// rowScanner lets scanGuestRequest work over both QueryRow and Query results.
type rowScanner interface{ Scan(dest ...any) error }

func (s *Store) scanGuestRequest(row rowScanner) (GuestRequest, error) {
	var r GuestRequest
	var requested, decided, untilTS string
	err := row.Scan(&r.ID, &r.GrantID, &r.Owner, &r.PermitID, &r.Plate, &r.Status, &requested, &decided, &r.DecidedBy, &r.Until, &untilTS)
	if err == sql.ErrNoRows {
		return GuestRequest{}, ErrNotFound
	}
	if err != nil {
		return GuestRequest{}, err
	}
	r.RequestedAt, _ = time.Parse(time.RFC3339, requested)
	r.DecidedAt, _ = time.Parse(time.RFC3339, decided)
	r.UntilTS, _ = time.Parse(time.RFC3339, untilTS)
	return r, nil
}

// GuestRequestByID returns a request (used by the visitor's polling status page).
func (s *Store) GuestRequestByID(ctx context.Context, id int64) (GuestRequest, error) {
	return s.scanGuestRequest(s.db.QueryRowContext(ctx,
		`SELECT id, grant_id, owner, permit_id, plate, status, requested_at, decided_at, decided_by, until_at, until_ts
		 FROM guest_request WHERE id = ?`, id))
}

// ListPendingRequests returns an owner's still-pending printed-QR requests, newest
// first (the approvals queue).
func (s *Store) ListPendingRequests(ctx context.Context, owner string) ([]GuestRequest, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, grant_id, owner, permit_id, plate, status, requested_at, until_at FROM guest_request
		 WHERE owner = ? AND status = 'pending' ORDER BY id DESC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GuestRequest
	for rows.Next() {
		var r GuestRequest
		var requested string
		if err := rows.Scan(&r.ID, &r.GrantID, &r.Owner, &r.PermitID, &r.Plate, &r.Status, &requested, &r.Until); err != nil {
			return nil, err
		}
		r.RequestedAt, _ = time.Parse(time.RFC3339, requested)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListRecentDecidedRequests returns an owner's decided (approved/denied/expired)
// printed-QR requests since the given time, newest decision first. It feeds the
// guests page's recent-activity list, so every account member — not just the one
// who decided — can see how a request was resolved.
func (s *Store) ListRecentDecidedRequests(ctx context.Context, owner string, since time.Time) ([]GuestRequest, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, grant_id, owner, permit_id, plate, status, requested_at, decided_at, decided_by, until_at, until_ts
		 FROM guest_request
		 WHERE owner = ? AND status != 'pending' AND decided_at >= ?
		 ORDER BY decided_at DESC, id DESC`,
		owner, since.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GuestRequest
	for rows.Next() {
		r, err := s.scanGuestRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DecideGuestRequest approves or denies a pending request, scoped to owner. It
// records who decided and (on approval) when the granted window ends, so the
// decision stays legible later — to the visitor re-scanning the door code and
// to the other account members. It returns the request (so the caller can
// apply the plate on approval) or ErrNotFound if it is not the owner's or no
// longer pending.
func (s *Store) DecideGuestRequest(ctx context.Context, owner string, id int64, approve bool, until string, decidedBy string, untilTS time.Time) (GuestRequest, error) {
	status := "denied"
	if approve {
		status = "approved"
	}
	untilStamp := ""
	if !untilTS.IsZero() {
		untilStamp = untilTS.UTC().Format(time.RFC3339)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE guest_request SET status = ?, decided_at = ?, decided_by = ?, until_at = ?, until_ts = ?
		 WHERE id = ? AND owner = ? AND status = 'pending'`,
		status, nowUTC(), decidedBy, until, untilStamp, id, owner)
	if err != nil {
		return GuestRequest{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return GuestRequest{}, ErrNotFound
	}
	return s.GuestRequestByID(ctx, id)
}

// GuestContextByTokenHash resolves a presented token hash to the grant, recipient
// and allowed vehicles — only if the token is live, its grant enabled, and the
// owner's guest passes are not globally paused. Any failed gate returns
// ErrNotFound so the caller can show one neutral "no longer active" page.
func (s *Store) GuestContextByTokenHash(ctx context.Context, tokenHash string) (GuestContext, error) {
	var gc GuestContext
	var created, blUntil string
	var overnight, plate, reqOnly, enabled int
	err := s.db.QueryRowContext(ctx, `
SELECT t.id, t.recipient_email, g.id, g.owner, g.permit_id, g.label, g.allow_overnight, g.allow_plate, g.request_only, g.enabled, g.created_at, t.baseline_plate, t.baseline_until
FROM guest_token t
JOIN guest_grant g ON g.id = t.grant_id
WHERE t.token_hash = ? AND t.revoked_at = '' AND g.enabled = 1
  AND (t.expires_at = '' OR t.expires_at > ?)
  AND COALESCE((SELECT guests_enabled FROM account_flags WHERE owner = g.owner), 1) = 1`,
		tokenHash, nowUTC()).Scan(&gc.TokenID, &gc.Recipient, &gc.Grant.ID, &gc.Grant.Owner, &gc.Grant.PermitID,
		&gc.Grant.Label, &overnight, &plate, &reqOnly, &enabled, &created, &gc.BaselinePlate, &blUntil)
	if err == sql.ErrNoRows {
		return GuestContext{}, ErrNotFound
	}
	if err != nil {
		return GuestContext{}, err
	}
	gc.Grant.AllowOvernight = overnight == 1
	gc.Grant.AllowPlate = plate == 1
	gc.Grant.RequestOnly = reqOnly == 1
	gc.Grant.Enabled = enabled == 1
	if gc.Grant.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
		return GuestContext{}, err
	}
	if blUntil != "" {
		// A malformed timestamp reads as "no baseline" rather than failing the link.
		gc.BaselineUntil, _ = time.Parse(time.RFC3339, blUntil)
	}
	gc.Vehicles, err = s.queryVehicles(ctx, `
SELECT v.id, v.registration, v.label, v.email, v.color FROM vehicle v
JOIN guest_grant_vehicle gv ON gv.vehicle_id = v.id
WHERE gv.grant_id = ? ORDER BY v.label, v.registration`, gc.Grant.ID)
	return gc, err
}

// ListGuestGrants returns the owner's grants with their cars and recipient tokens.
func (s *Store) ListGuestGrants(ctx context.Context, owner string) ([]GuestGrantDetail, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, permit_id, label, allow_overnight, enabled, created_at FROM guest_grant WHERE owner = ? AND on_screen = 0 AND request_only = 0 ORDER BY id DESC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GuestGrantDetail
	for rows.Next() {
		var d GuestGrantDetail
		var overnight, enabled int
		var created string
		if err := rows.Scan(&d.Grant.ID, &d.Grant.PermitID, &d.Grant.Label, &overnight, &enabled, &created); err != nil {
			return nil, err
		}
		d.Grant.Owner = owner
		d.Grant.AllowOvernight = overnight == 1
		d.Grant.Enabled = enabled == 1
		if d.Grant.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		g := &out[i]
		g.Vehicles, err = s.queryVehicles(ctx, `
SELECT v.id, v.registration, v.label, v.email, v.color FROM vehicle v
JOIN guest_grant_vehicle gv ON gv.vehicle_id = v.id
WHERE gv.grant_id = ? ORDER BY v.label, v.registration`, g.Grant.ID)
		if err != nil {
			return nil, err
		}
		g.Tokens, err = s.listGuestTokens(ctx, g.Grant.ID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) listGuestTokens(ctx context.Context, grantID int64) ([]GuestToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, grant_id, recipient_email, revoked_at, created_at FROM guest_token WHERE grant_id = ? ORDER BY id`, grantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GuestToken
	for rows.Next() {
		var t GuestToken
		var revoked, created string
		if err := rows.Scan(&t.ID, &t.GrantID, &t.RecipientEmail, &revoked, &created); err != nil {
			return nil, err
		}
		t.Revoked = revoked != ""
		if t.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GuestTokenRecipient returns the address a link was issued to, scoped to the
// grant's owner. Revoking is one of the few actions that takes access AWAY from a
// named third party, so the audit row and the household notice have to be able to
// say whose link died — an entry that records only "a link was revoked" tells the
// member who didn't do it nothing they can check. Empty for the machine-minted
// grants (on-screen / printed QR), which have no recipient.
func (s *Store) GuestTokenRecipient(ctx context.Context, owner string, tokenID int64) (string, error) {
	var email string
	err := s.db.QueryRowContext(ctx, `
SELECT t.recipient_email FROM guest_token t
JOIN guest_grant g ON g.id = t.grant_id
WHERE t.id = ? AND g.owner = ?`, tokenID, owner).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return email, err
}

// GrantTokenID returns the id of a grant's token — for the machine-minted grants
// (printed door QR, on-screen QR) there is exactly one, and the newest wins
// otherwise. It exists so an approval made through a door QR can TAG the override
// it creates with the token that led to it: an untagged (guest_token_id = 0)
// override is indistinguishable from the household's own bookings, so revoking
// the poster could not take the visitor's plate back off the permit.
func (s *Store) GrantTokenID(ctx context.Context, grantID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM guest_token WHERE grant_id = ? ORDER BY id DESC LIMIT 1`, grantID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

// Revocation has to be RETROACTIVE. A guest link's real power is not the page it
// opens, it is the override row the guest left behind: that row keeps steering the
// permit until the end of its window (which can be the end of tomorrow), and every
// reconcile pass re-asserts it. Without these sweeps "this link no longer works"
// was true of the link and false of the permit, which is the opposite of what a
// household hitting revoke is asking for — and the abusing guest stayed parked on
// their permit for up to another day.
//
// Only rows that still carry authority are removed (running now or starting
// later). A guest change that has already ended is history, and history is what
// the activity log is for.
const sweepLiveGuestOverrides = `
DELETE FROM override
WHERE guest_token_id != 0 AND (ends_at IS NULL OR ends_at = '' OR ends_at > ?)
  AND guest_token_id `

// RevokeGuestToken revokes one recipient's link, scoped to the grant's owner, and
// sweeps the still-live overrides that link created.
//
// Restricted to the emailed passes with the same filter ResetGuestToken uses. The
// printed door QR and the on-screen QR are not per-recipient links: killing one
// through this route retired a whole PRINTED code — the one artifact a household
// has physically put on a wall — while logging an empty target and sending no
// notification, where revokeDoorQR names it and tells the household. The narrower
// route must not be the quiet way to do the wider thing.
func (s *Store) RevokeGuestToken(ctx context.Context, owner string, tokenID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
UPDATE guest_token SET revoked_at = ?
WHERE id = ? AND revoked_at = ''
  AND grant_id IN (SELECT id FROM guest_grant WHERE owner = ? AND on_screen = 0 AND request_only = 0)`,
		nowUTC(), tokenID, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	// Sweep every token this recipient has held on the grant, not just the row being
	// revoked. ResetGuestToken retires superseded duplicates in place rather than
	// deleting them (their bookings must stay reachable), so a booking made through an
	// earlier row is bound to an id the household's revoke button never names. Revoking
	// a recipient has to mean the recipient, not one link they happen to hold.
	if _, err := tx.ExecContext(ctx, sweepLiveGuestOverrides+`IN (
        SELECT sib.id FROM guest_token sib
        JOIN guest_token cur ON cur.grant_id = sib.grant_id
                            AND cur.recipient_email = sib.recipient_email
        WHERE cur.id = ?)`, nowUTC(), tokenID); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteGuestGrant removes a grant (its vehicles and tokens cascade), scoped to
// owner, and sweeps the still-live overrides any of its links created.
func (s *Store) DeleteGuestGrant(ctx context.Context, owner string, grantID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Before the grant goes: its tokens cascade away with it, and override rows
	// carry no foreign key, so afterwards there is nothing left to match them on.
	if _, err := tx.ExecContext(ctx,
		sweepLiveGuestOverrides+`IN (SELECT t.id FROM guest_token t JOIN guest_grant g ON g.id = t.grant_id
		     WHERE t.grant_id = ? AND g.owner = ?)`,
		nowUTC(), grantID, owner); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM guest_grant WHERE id = ? AND owner = ?`, grantID, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// SetGuestBaseline remembers what was on the permit before a guest link's run of
// activations (and how long that run's window lasts), so the guest can revert.
func (s *Store) SetGuestBaseline(ctx context.Context, tokenID int64, plate string, until time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE guest_token SET baseline_plate = ?, baseline_until = ? WHERE id = ?`,
		plate, until.UTC().Format(time.RFC3339), tokenID)
	return err
}

// CaptureOrExtendGuestBaseline atomically records the revert baseline for one
// activation: when no window is active (empty or expired) it captures plate +
// until; when a window is active it only extends the end if the new end is
// later — never the plate, so two near-simultaneous activations can't record
// the guest's own first pick as the "pre-existing" plate (the race a separate
// read-modify-write through SetGuestBaseline allows). Returns the effective
// baseline after the update. Timestamps are RFC3339 UTC, so the lexicographic
// SQL comparisons are chronologically correct.
func (s *Store) CaptureOrExtendGuestBaseline(ctx context.Context, tokenID int64, plate string, until, now time.Time) (string, time.Time, error) {
	var p, u string
	err := s.db.QueryRowContext(ctx, `
UPDATE guest_token SET
  baseline_plate = CASE WHEN baseline_until = '' OR baseline_until < ?3 THEN ?1 ELSE baseline_plate END,
  baseline_until = CASE
      WHEN baseline_until = '' OR baseline_until < ?3 THEN ?2
      WHEN ?2 > baseline_until THEN ?2
      ELSE baseline_until END
WHERE id = ?4
RETURNING baseline_plate, baseline_until`,
		plate, until.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), tokenID).
		Scan(&p, &u)
	if err != nil {
		return "", time.Time{}, err
	}
	ut, _ := time.Parse(time.RFC3339, u)
	return p, ut, nil
}

// ClearGuestBaseline forgets a link's captured baseline (after a revert), so the
// next activation captures a fresh one.
func (s *Store) ClearGuestBaseline(ctx context.Context, tokenID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE guest_token SET baseline_plate = '', baseline_until = '' WHERE id = ?`, tokenID)
	return err
}

// GuestsEnabled reports the owner's global kill-switch (default on).
func (s *Store) GuestsEnabled(ctx context.Context, owner string) (bool, error) {
	var v int
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT guests_enabled FROM account_flags WHERE owner = ?), 1)`, owner).Scan(&v)
	return v == 1, err
}

// SetGuestsEnabled flips the owner's global kill-switch for guest passes. Pausing
// also sweeps the still-live overrides every guest link on the account created:
// this is the panic button, and a panic button that leaves a stranger's plate on
// the permit until the end of tomorrow is not one. Resuming touches nothing —
// the swept bookings are gone, and re-creating them is the guest's to do.
func (s *Store) SetGuestsEnabled(ctx context.Context, owner string, enabled bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO account_flags (owner, guests_enabled) VALUES (?, ?)
ON CONFLICT(owner) DO UPDATE SET guests_enabled = excluded.guests_enabled`, owner, boolInt(enabled)); err != nil {
		return err
	}
	if !enabled {
		if _, err := tx.ExecContext(ctx,
			sweepLiveGuestOverrides+`IN (SELECT t.id FROM guest_token t JOIN guest_grant g ON g.id = t.grant_id
			     WHERE g.owner = ?)`,
			nowUTC(), owner); err != nil {
			return err
		}
	}
	return tx.Commit()
}
