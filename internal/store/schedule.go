package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
)

// ---- Weekly rules ----

func (s *Store) ListRules(ctx context.Context, permitID int64) ([]model.WeeklyRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, permit_id, weekday, vehicle_id FROM weekly_rule WHERE permit_id = ? ORDER BY weekday`, permitID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.WeeklyRule
	for rows.Next() {
		var r model.WeeklyRule
		var wd int
		if err := rows.Scan(&r.ID, &r.PermitID, &wd, &r.VehicleID); err != nil {
			return nil, err
		}
		r.Weekday = time.Weekday(wd)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetRule sets (or replaces) the vehicle for a permit on a weekday.
func (s *Store) SetRule(ctx context.Context, permitID int64, weekday time.Weekday, vehicleID int64) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO weekly_rule (permit_id, weekday, vehicle_id) VALUES (?, ?, ?)
ON CONFLICT(permit_id, weekday) DO UPDATE SET vehicle_id = excluded.vehicle_id`,
		permitID, int(weekday), vehicleID)
	return err
}

// ClearRule removes any rule for a permit on a weekday.
func (s *Store) ClearRule(ctx context.Context, permitID int64, weekday time.Weekday) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM weekly_rule WHERE permit_id = ? AND weekday = ?`, permitID, int(weekday))
	return err
}

// CopySchedule REPLACES a permit's weekly roster and active/upcoming overrides
// with a copy of another permit's — the "I renewed my permit and re-added it, put
// my schedule back" flow. Both permits must belong to owner. It clears the
// target's existing rules and live overrides first, so it is idempotent (running
// it twice yields the same result, not duplicates) and matches the "replaces this
// permit's schedule" wording in the UI. Overrides that have already ended are not
// carried (nothing left to apply); the target's past overrides are left as
// history. Vehicle references are account-scoped, so they stay valid on the
// target. Returns the number of rules + overrides copied.
func (s *Store) CopySchedule(ctx context.Context, owner string, srcID, dstID int64, now time.Time) (int, error) {
	if srcID == dstID {
		return 0, errors.New("store: cannot copy a schedule onto itself")
	}
	nowStr := now.UTC().Format(time.RFC3339)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Both permits must belong to the owner (defence in depth over the handler).
	var owned int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM permit WHERE id IN (?, ?) AND owner = ?`, srcID, dstID, owner).Scan(&owned); err != nil {
		return 0, err
	}
	if owned != 2 {
		return 0, ErrNotFound
	}

	// Clear the target's current roster + live overrides so this is a clean replace.
	if _, err := tx.ExecContext(ctx, `DELETE FROM weekly_rule WHERE permit_id = ?`, dstID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM override WHERE permit_id = ? AND (ends_at IS NULL OR ends_at > ?)`, dstID, nowStr); err != nil {
		return 0, err
	}

	rres, err := tx.ExecContext(ctx, `
INSERT INTO weekly_rule (permit_id, weekday, vehicle_id)
SELECT ?, weekday, vehicle_id FROM weekly_rule WHERE permit_id = ?`, dstID, srcID)
	if err != nil {
		return 0, err
	}
	ores, err := tx.ExecContext(ctx, `
INSERT INTO override (permit_id, vehicle_id, registration, starts_at, ends_at, created_by, created_at)
SELECT ?, vehicle_id, registration, starts_at, ends_at, created_by, created_at
FROM override WHERE permit_id = ? AND (ends_at IS NULL OR ends_at > ?)`,
		dstID, srcID, nowStr)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	rn, _ := rres.RowsAffected()
	on, _ := ores.RowsAffected()
	return int(rn + on), nil
}

// ---- Overrides ----

func (s *Store) CreateOverride(ctx context.Context, permitID, vehicleID int64, startsAt time.Time, endsAt *time.Time, createdBy string) (int64, error) {
	return s.CreateGuestOverride(ctx, permitID, vehicleID, startsAt, endsAt, createdBy, 0)
}

// ErrOverrideLimit is returned by CreateOverrideCapped when a permit already holds
// the maximum number of simultaneously-live overrides.
var ErrOverrideLimit = errors.New("store: permit has too many live overrides")

// CreateOverrideCapped creates an override only if the permit is below `limit` live
// overrides (no end, or ending in the future) — doing the count and the insert in ONE
// transaction so two concurrent creates cannot both slip past the cap (each statement
// otherwise releases the single connection between them). A non-zero vehicleID uses a
// saved vehicle; vehicleID 0 with a non-empty registration is a one-off plate. Returns
// ErrOverrideLimit when full.
func (s *Store) CreateOverrideCapped(ctx context.Context, permitID, vehicleID int64, registration string, startsAt time.Time, endsAt *time.Time, createdBy string, limit int) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM override WHERE permit_id = ? AND (ends_at IS NULL OR ends_at > ?)`,
		permitID, nowUTC()).Scan(&n); err != nil {
		return 0, err
	}
	if n >= limit {
		return 0, ErrOverrideLimit
	}
	var vid any // NULL for a plate booking
	if vehicleID != 0 {
		vid = vehicleID
	}
	res, err := tx.ExecContext(ctx, `
INSERT INTO override (permit_id, vehicle_id, registration, starts_at, ends_at, created_by, created_at, guest_token_id)
VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		permitID, vid, registration, startsAt.UTC().Format(time.RFC3339), endsAtSQL(endsAt), createdBy, nowUTC())
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// CreateGuestOverride is CreateOverride tagged with the guest link that made it,
// so a guest's revert can remove exactly their own changes.
func (s *Store) CreateGuestOverride(ctx context.Context, permitID, vehicleID int64, startsAt time.Time, endsAt *time.Time, createdBy string, guestTokenID int64) (int64, error) {
	return s.createOverrideGuarded(ctx, permitID, vehicleID, "", startsAt, endsAt, createdBy, guestTokenID)
}

// createOverrideGuarded inserts a guest-created override only if that guest link is
// STILL live and the permit is under its live-override cap, both decided inside the
// insert itself.
//
// The liveness guard closes a revocation race with a real cost: the handler checks the
// token when it resolves the request, but the insert happens several statements later
// (rate limit, form parse, and queueing behind the single SQLite connection). A revoke
// landing in that gap sweeps live overrides — finds none, because this one does not
// exist yet — tells the household "any car it had put on your permit has been taken
// off", and then this insert lands anyway. Nothing joins guest_token when resolving a
// permit's target, so that orphan then steers the permit until its window ends (up to
// ~2 days with the overnight box): the user's explicit revocation, silently undone.
func (s *Store) createOverrideGuarded(ctx context.Context, permitID, vehicleID int64, registration string, startsAt time.Time, endsAt *time.Time, createdBy string, guestTokenID int64) (int64, error) {
	var vid any // NULL for a plate booking
	if vehicleID != 0 {
		vid = vehicleID
	}
	// The liveness EXISTS applies ONLY to real guest creates: guest_token_id 0 is a
	// member-created override (CreateOverride delegates here), which has no token to
	// check and must not be refused by one. The cap applies to both.
	res, err := s.db.ExecContext(ctx, `
INSERT INTO override (permit_id, vehicle_id, registration, starts_at, ends_at, created_by, created_at, guest_token_id)
SELECT ?, ?, ?, ?, ?, ?, ?, ?
WHERE (? = 0 OR EXISTS (
        SELECT 1 FROM guest_token t JOIN guest_grant g ON g.id = t.grant_id
        WHERE t.id = ? AND t.revoked_at = '' AND g.enabled = 1))
  AND (SELECT COUNT(*) FROM override
       WHERE permit_id = ? AND (ends_at IS NULL OR ends_at > ?)) < ?`,
		permitID, vid, registration, startsAt.UTC().Format(time.RFC3339), endsAtSQL(endsAt), createdBy, nowUTC(), guestTokenID,
		guestTokenID, guestTokenID, permitID, nowUTC(), MaxLiveOverridesPerPermit)
	if err != nil {
		return 0, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return 0, err
	} else if n == 0 {
		return 0, ErrGuestOverrideRefused
	}
	return res.LastInsertId()
}

// ErrGuestOverrideRefused means a guest-created override was not written: the link was
// revoked/disabled between resolving it and the insert, or the permit is at its live-
// override cap. The caller must NOT go on to change the plate at the council.
var ErrGuestOverrideRefused = errors.New("store: guest link is no longer active, or the permit has too many live bookings")

// MaxLiveOverridesPerPermit caps simultaneously-active bookings on one permit so the
// never-pruned, hot-path override table cannot grow without bound. It applies to guest
// creates as well as member ones — capping only the member path left the public guest
// and door-QR flows able to insert without limit, which is the larger surface.
const MaxLiveOverridesPerPermit = 50

// CreatePlateOverride books a one-off using a literal, unsaved number plate
// (vehicle_id IS NULL). The plate is normalised by the caller.
func (s *Store) CreatePlateOverride(ctx context.Context, permitID int64, registration string, startsAt time.Time, endsAt *time.Time, createdBy string) (int64, error) {
	return s.CreateGuestPlateOverride(ctx, permitID, registration, startsAt, endsAt, createdBy, 0)
}

// CreateGuestPlateOverride is CreatePlateOverride tagged with the guest link
// that made it (see CreateGuestOverride).
func (s *Store) CreateGuestPlateOverride(ctx context.Context, permitID int64, registration string, startsAt time.Time, endsAt *time.Time, createdBy string, guestTokenID int64) (int64, error) {
	return s.createOverrideGuarded(ctx, permitID, 0, registration, startsAt, endsAt, createdBy, guestTokenID)
}

// DeleteGuestOverrides removes every override a guest link created on a permit
// (the sweep behind a guest's "put it back" revert). A zero tokenID is refused:
// it would match every non-guest override.
func (s *Store) DeleteGuestOverrides(ctx context.Context, permitID, guestTokenID int64) error {
	if guestTokenID == 0 {
		return errors.New("store: DeleteGuestOverrides requires a guest token id")
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM override WHERE permit_id = ? AND guest_token_id = ?`, permitID, guestTokenID)
	return err
}

func endsAtSQL(endsAt *time.Time) sql.NullString {
	if endsAt == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: endsAt.UTC().Format(time.RFC3339), Valid: true}
}

// ListOverrides returns a permit's active and upcoming overrides (those not yet
// ended, however far in the future), soonest first, a chronological list the
// user can scan and manage.
func (s *Store) ListOverrides(ctx context.Context, permitID int64, now time.Time) ([]model.Override, error) {
	nowStr := now.UTC().Format(time.RFC3339)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, permit_id, vehicle_id, registration, starts_at, ends_at, created_by, created_at
FROM override
WHERE permit_id = ? AND (ends_at IS NULL OR ends_at > ?)
ORDER BY starts_at ASC`, permitID, nowStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Override
	for rows.Next() {
		var o model.Override
		var starts, created string
		var ends sql.NullString
		var vid sql.NullInt64
		if err := rows.Scan(&o.ID, &o.PermitID, &vid, &o.Registration, &starts, &ends, &o.CreatedBy, &created); err != nil {
			return nil, err
		}
		o.VehicleID = vid.Int64 // 0 when NULL (an ad-hoc plate)
		if o.StartsAt, err = time.Parse(time.RFC3339, starts); err != nil {
			return nil, err
		}
		if o.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
			return nil, err
		}
		if ends.Valid {
			t, err := time.Parse(time.RFC3339, ends.String)
			if err != nil {
				return nil, err
			}
			o.EndsAt = &t
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ActiveGuestOverridePlate returns the registration of the currently-active
// override this guest link created on a permit (started, not yet ended), newest
// first, and whether one exists. Used to decide whether a guest's "put it back"
// revert is still meaningful: if the link no longer has a live override, the
// guest's activation has already been superseded (e.g. by a later owner booking)
// and revert must not be offered — reverting would displace that booking.
func (s *Store) ActiveGuestOverridePlate(ctx context.Context, permitID, guestTokenID int64, now time.Time) (string, bool) {
	if guestTokenID == 0 {
		return "", false
	}
	var reg string
	err := s.db.QueryRowContext(ctx, `
SELECT registration FROM override
WHERE permit_id = ? AND guest_token_id = ? AND registration != ''
  AND starts_at <= ? AND (ends_at IS NULL OR ends_at > ?)
ORDER BY created_at DESC, id DESC LIMIT 1`,
		permitID, guestTokenID, now.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)).Scan(&reg)
	if err != nil {
		return "", false
	}
	return reg, reg != ""
}

// PruneOverrides deletes overrides that ended before `before`. Every guest
// activation writes one, and a printed door QR is public, so without a sweep the
// table grows forever from anonymous traffic — and ListOverrides is on the hot
// path of both every dashboard render and every scheduler pass. Open-ended rows
// (ends_at IS NULL) are never pruned: they are still live schedule state.
func (s *Store) PruneOverrides(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM override WHERE ends_at IS NOT NULL AND ends_at != '' AND ends_at < ?`,
		before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteOverride removes an override, scoped to the owner of its permit (guards
// against deleting another user's override by id).
func (s *Store) DeleteOverride(ctx context.Context, owner string, id int64) error {
	_, err := s.db.ExecContext(ctx, `
DELETE FROM override
WHERE id = ? AND permit_id IN (SELECT id FROM permit WHERE owner = ?)`, id, owner)
	return err
}

// DeleteOverrideOnPermit deletes a booking that belongs to BOTH the owner and the
// named permit, and reports whether a row actually went.
//
// The permit predicate matters even though the owner one already prevents any
// cross-account reach: the delete route is /permits/{id}/overrides/{oid}/delete, and
// with only the owner check an {oid} from a DIFFERENT permit of the same account was
// happily deleted while the response re-rendered permit {id} — so the booking
// vanished from a card the user was not looking at, with nothing on screen to say so.
//
// The bool is what lets the caller stay silent about a no-op. DeleteOverride returns
// nil whether or not it matched, so the handler used to write an audit row and kick
// the scheduler for an id that never existed — replayable to bury a household's real
// activity under invented entries.
func (s *Store) DeleteOverrideOnPermit(ctx context.Context, owner string, permitID, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
DELETE FROM override
WHERE id = ? AND permit_id = ? AND permit_id IN (SELECT id FROM permit WHERE owner = ?)`,
		id, permitID, owner)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// GuestOverrideStillAuthorised reports whether a guest-created override is STILL
// authorised to be applied, checking the WHOLE capability rather than just existence:
// the row survives (every revocation path sweeps live overrides by token), the token is
// unrevoked, the grant is enabled and still covers this permit, the account-level guest
// switch is on, and the specific capability exercised is still granted — the chosen
// saved vehicle is still in the pass, or arbitrary plates are still allowed.
//
// The guarded insert proves all that at INSERT time, but the council write happens
// seconds later, and an owner can revoke or EDIT the pass in between (removing the very
// vehicle the guest picked). Called under the permit apply claim immediately before the
// council write.
func (s *Store) GuestOverrideStillAuthorised(ctx context.Context, overrideID, guestTokenID int64) (bool, error) {
	if overrideID == 0 || guestTokenID == 0 {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM override o
JOIN guest_token t ON t.id = o.guest_token_id
JOIN guest_grant g ON g.id = t.grant_id
WHERE o.id = ? AND o.guest_token_id = ?
  AND t.revoked_at = '' AND g.enabled = 1 AND g.permit_id = o.permit_id
  AND COALESCE((SELECT guests_enabled FROM account_flags WHERE owner = g.owner), 1) = 1
  AND ((o.vehicle_id IS NOT NULL
        AND EXISTS (SELECT 1 FROM guest_grant_vehicle gv
                    WHERE gv.grant_id = g.id AND gv.vehicle_id = o.vehicle_id))
    OR (o.vehicle_id IS NULL AND g.allow_plate = 1))`,
		overrideID, guestTokenID).Scan(&n)
	return n > 0, err
}

// GuestTokenStillLive reports whether a guest link still carries any authority at all:
// unrevoked token, enabled grant, account switch on. Used before a council write that
// is not exercising a specific capability — a REVERT puts back the plate that was there
// before the guest touched it, so it must not be gated on the vehicle/plate permissions
// an activation needs (a pass without allow_plate can still undo itself).
func (s *Store) GuestTokenStillLive(ctx context.Context, guestTokenID int64) (bool, error) {
	if guestTokenID == 0 {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM guest_token t
JOIN guest_grant g ON g.id = t.grant_id
WHERE t.id = ? AND t.revoked_at = '' AND g.enabled = 1
  AND COALESCE((SELECT guests_enabled FROM account_flags WHERE owner = g.owner), 1) = 1`,
		guestTokenID).Scan(&n)
	return n > 0, err
}

// GuestGrantPermit / GuestTokenPermit resolve the permit a revocation affects, so the
// handler can take that permit's apply claim BEFORE revoking — which is what makes the
// revocation and any in-flight guest apply serialise against each other.
func (s *Store) GuestGrantPermit(ctx context.Context, owner string, grantID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT permit_id FROM guest_grant WHERE id = ? AND owner = ?`, grantID, owner).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

func (s *Store) GuestTokenPermit(ctx context.Context, owner string, tokenID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
SELECT g.permit_id FROM guest_token t JOIN guest_grant g ON g.id = t.grant_id
WHERE t.id = ? AND g.owner = ?`, tokenID, owner).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}
