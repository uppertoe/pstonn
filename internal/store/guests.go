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
func (s *Store) UpdateGuestGrant(ctx context.Context, owner string, grantID int64, label string, allowOvernight bool, vehicleIDs []int64) (swept int64, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`UPDATE guest_grant SET label = ?, allow_overnight = ?
		 WHERE id = ? AND owner = ? AND on_screen = 0 AND request_only = 0`,
		label, boolInt(allowOvernight), grantID, owner)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM guest_grant_vehicle WHERE grant_id = ?`, grantID); err != nil {
		return 0, err
	}
	for _, vid := range vehicleIDs {
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
	// Unticking a car is a withdrawal of authority, so sweep the LIVE overrides this
	// grant's links already steered with a car that is no longer allowed — otherwise the
	// reconcile loop keeps re-asserting the removed car onto the permit for up to ~30
	// more hours (ListOverrides does not join guest_token, so nothing else would ever
	// catch it), while the owner is flashed "Guest pass updated." Only vehicle-backed
	// rows are swept: a typed-plate booking is not tied to a saved car. The new allowed
	// set was just written above, so `guest_grant_vehicle` is the authority to check.
	sweep, err := tx.ExecContext(ctx, `
DELETE FROM override
WHERE guest_token_id != 0
  AND (ends_at IS NULL OR ends_at = '' OR ends_at > ?)
  AND vehicle_id IS NOT NULL
  AND guest_token_id IN (SELECT id FROM guest_token WHERE grant_id = ?)
  AND vehicle_id NOT IN (SELECT vehicle_id FROM guest_grant_vehicle WHERE grant_id = ?)`,
		nowUTC(), grantID, grantID)
	if err != nil {
		return 0, err
	}
	swept, _ = sweep.RowsAffected()
	return swept, tx.Commit()
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
SELECT v.id, v.registration, v.label, v.email, v.color, v.state, v.notify_driver FROM vehicle v
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
SELECT v.id, v.registration, v.label, v.email, v.color, v.state, v.notify_driver FROM vehicle v
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

// MoveGuestGrants re-points every guest grant (passes, door QR, even ephemeral
// on-screen codes) from one of the owner's permits onto another. The grants'
// tokens are untouched, and a token IS a link's identity — so a pass saved to a
// guest's phone home screen and a door poster taped up months ago keep working
// across a tenant cancel-and-reissue, with nothing re-sent or re-printed.
// Both permits must belong to owner.
//
// Three things ride along with the grants, in one transaction:
//   - Live revert baselines on the moved grants' tokens are CLEARED. A baseline
//     means "the plate that was on this permit when the link's current run of
//     activations began" — permit-specific by meaning even though it is stored
//     on the token — so carrying one across would let a guest's "put the
//     previous car back" write the OLD permit's plate onto the new permit.
//   - PENDING printed-QR requests follow their grant, so a visitor waiting at
//     the door when the renewal lands can still be approved. Decided rows are
//     history on the old permit and stay put.
//   - One printed door QR per permit is preserved: if the destination already
//     has its own, the source's is left behind (where the inactive-permit gate
//     keeps it safely refused) and strandedPoster reports it, so the caller can
//     tell the household the old poster is dead instead of claiming it works.
func (s *Store) MoveGuestGrants(ctx context.Context, owner string, srcID, dstID int64) (moved int, strandedPoster bool, err error) {
	if srcID == dstID {
		return 0, false, errors.New("store: cannot move guest passes onto the same permit")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()

	var owned int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM permit WHERE id IN (?, ?) AND owner = ?`, srcID, dstID, owner).Scan(&owned); err != nil {
		return 0, false, err
	}
	if owned != 2 {
		return 0, false, ErrNotFound
	}
	var dstPrinted int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM guest_grant WHERE owner = ? AND permit_id = ? AND request_only = 1`,
		owner, dstID).Scan(&dstPrinted); err != nil {
		return 0, false, err
	}
	filter := ``
	if dstPrinted > 0 {
		filter = ` AND request_only = 0`
		var srcPrinted int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM guest_grant WHERE owner = ? AND permit_id = ? AND request_only = 1`,
			owner, srcID).Scan(&srcPrinted); err != nil {
			return 0, false, err
		}
		strandedPoster = srcPrinted > 0
	}
	// Baselines and pending requests are updated BEFORE the grants move, while
	// "the grants being moved" is still expressible as a subquery on the source.
	movingGrants := `(SELECT id FROM guest_grant WHERE owner = ? AND permit_id = ?` + filter + `)`
	if _, err := tx.ExecContext(ctx,
		`UPDATE guest_token SET baseline_plate = '', baseline_until = '' WHERE grant_id IN `+movingGrants,
		owner, srcID); err != nil {
		return 0, false, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE guest_request SET permit_id = ? WHERE status = 'pending' AND permit_id = ? AND grant_id IN `+movingGrants,
		dstID, srcID, owner, srcID); err != nil {
		return 0, false, err
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE guest_grant SET permit_id = ? WHERE owner = ? AND permit_id = ?`+filter,
		dstID, owner, srcID)
	if err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	n, _ := res.RowsAffected()
	return int(n), strandedPoster, nil
}
