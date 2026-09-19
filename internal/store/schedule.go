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
		`SELECT id, permit_id, cycle_week, weekday, vehicle_id, empty FROM weekly_rule WHERE permit_id = ? ORDER BY cycle_week, weekday`, permitID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.WeeklyRule
	for rows.Next() {
		var r model.WeeklyRule
		var wd int
		var vid sql.NullInt64
		if err := rows.Scan(&r.ID, &r.PermitID, &r.Week, &wd, &vid, &r.Empty); err != nil {
			return nil, err
		}
		r.Weekday = time.Weekday(wd)
		r.VehicleID = vid.Int64 // 0 when NULL (an empty day)
		if r.VehicleID == 0 && !r.Empty {
			continue // neither a rego nor an empty day: a row no writer produces, ignored rather than resolved to nothing
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ErrCycleWeek reports a rule write aimed at a cycle week the permit does not
// have — a stale tab from before a week was removed. Refused rather than
// written: an unreachable rule row would silently do nothing until a later
// cycle change made it resurface as a surprise.
var ErrCycleWeek = errors.New("store: no such cycle week on this permit")

// SetRule sets (or replaces) the vehicle for a permit on a weekday of a cycle
// week. The insert is guarded in SQL against the permit's own cycle_weeks so a
// stale form can never write an orphan week (single round trip; the guard and
// the write cannot race apart on the one-connection pool).
func (s *Store) SetRule(ctx context.Context, owner string, permitID int64, week int, weekday time.Weekday, vehicleID int64) error {
	// Ownership is checked here, at the write, not only in the handler: the
	// permit must be the owner's, and so must the rego it names.
	if err := s.ownsPermit(ctx, owner, permitID); err != nil {
		return err
	}
	var vehOK int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM vehicle WHERE id = ? AND owner = ?)`, vehicleID, owner).Scan(&vehOK); err != nil {
		return err
	}
	if vehOK == 0 {
		return ErrNotFound
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO weekly_rule (permit_id, cycle_week, weekday, vehicle_id, empty)
SELECT ?, ?, ?, ?, 0 WHERE ? < (SELECT cycle_weeks FROM permit WHERE id = ? AND owner = ?)
ON CONFLICT(permit_id, cycle_week, weekday) DO UPDATE SET vehicle_id = excluded.vehicle_id, empty = 0`,
		permitID, week, int(weekday), vehicleID, week, permitID, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrCycleWeek
	}
	return nil
}

// SetEmptyRule makes a weekday of a cycle week an "empty" day: the permit is
// left with no rego on it. The same guards as SetRule, minus the vehicle.
func (s *Store) SetEmptyRule(ctx context.Context, owner string, permitID int64, week int, weekday time.Weekday) error {
	if err := s.ownsPermit(ctx, owner, permitID); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO weekly_rule (permit_id, cycle_week, weekday, vehicle_id, empty)
SELECT ?, ?, ?, NULL, 1 WHERE ? < (SELECT cycle_weeks FROM permit WHERE id = ? AND owner = ?)
ON CONFLICT(permit_id, cycle_week, weekday) DO UPDATE SET vehicle_id = NULL, empty = 1`,
		permitID, week, int(weekday), week, permitID, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrCycleWeek
	}
	return nil
}

func (s *Store) ClearRule(ctx context.Context, owner string, permitID int64, week int, weekday time.Weekday) error {
	if err := s.ownsPermit(ctx, owner, permitID); err != nil {
		return err
	}
	// Clearing a day that is already empty is a valid no-op (the roster cell
	// offers "none" on every day), so no row affected is not an error here.
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM weekly_rule WHERE permit_id = ? AND cycle_week = ? AND weekday = ?
		   AND permit_id IN (SELECT id FROM permit WHERE owner = ?)`,
		permitID, week, int(weekday), owner)
	return err
}

// ownsPermit is the IDOR guard for writes that address a permit by id: the row
// must be the owner's, or the caller gets the same ErrNotFound a missing row
// gives, so "not yours" and "not there" are one neutral answer.
func (s *Store) ownsPermit(ctx context.Context, owner string, permitID int64) error {
	var ok int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM permit WHERE id = ? AND owner = ?)`, permitID, owner).Scan(&ok); err != nil {
		return err
	}
	if ok == 0 {
		return ErrNotFound
	}
	return nil
}

// OwnerHasSchedule reports whether ANY of the owner's permits carries a weekly
// rule or a live (running or future) one-off booking. It scopes the "nothing
// scheduled yet" nudge to households that have never scheduled anything: once
// one permit is set up the mechanics are learnt, and repeating the banner on
// every other empty card would just nag.
func (s *Store) OwnerHasSchedule(ctx context.Context, owner string, now time.Time) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM weekly_rule w JOIN permit p ON p.id = w.permit_id WHERE p.owner = ?
    UNION ALL
    SELECT 1 FROM override o JOIN permit p ON p.id = o.permit_id
    WHERE p.owner = ? AND (o.ends_at IS NULL OR o.ends_at > ?)
)`, owner, owner, now.UTC().Format(time.RFC3339)).Scan(&n)
	return n == 1, err
}

// CopySchedule REPLACES a permit's weekly roster and active/upcoming overrides
// with a copy of another permit's — the "I renewed my permit and re-added it, put
// my schedule back" flow. Both permits must belong to owner. It clears the
// target's existing rules and live overrides first, so it is idempotent (running
// it twice yields the same result, not duplicates) and matches the "replaces this
// permit's schedule" wording in the UI. Overrides that have already ended are not
// carried (nothing left to apply); the target's past overrides are left as
// history. Vehicle references are account-scoped, so they stay valid on the
// target. An EMPTY source is a no-op that returns 0 without touching the target.
// Returns the number of rules + overrides copied.
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

	// An empty source copies nothing, so it must also REPLACE nothing: clearing
	// the target first and then finding zero rows to insert silently wiped a
	// roster the household had already built (and the caller, seeing 0, reported
	// "nothing to copy" over the wreckage). Nothing-in, nothing-touched.
	var srcRows int
	if err := tx.QueryRowContext(ctx, `
SELECT (SELECT COUNT(*) FROM weekly_rule WHERE permit_id = ?)
     + (SELECT COUNT(*) FROM override WHERE permit_id = ? AND (ends_at IS NULL OR ends_at > ?))`,
		srcID, srcID, nowStr).Scan(&srcRows); err != nil {
		return 0, err
	}
	if srcRows == 0 {
		return 0, nil
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
INSERT INTO weekly_rule (permit_id, cycle_week, weekday, vehicle_id, empty)
SELECT ?, cycle_week, weekday, vehicle_id, empty FROM weekly_rule WHERE permit_id = ?`, dstID, srcID)
	if err != nil {
		return 0, err
	}
	// The cycle shape is part of the schedule: without it, weeks 2+ of the copied
	// rules would be unreachable on the target. The anchor is copied verbatim so
	// source and target stay in phase — "put my schedule back" means the same car
	// on the same real-world week, not a cycle restarted from today. Placed after
	// the empty-source guard, so an empty source touches nothing at all.
	if _, err := tx.ExecContext(ctx, `
UPDATE permit SET cycle_weeks = (SELECT cycle_weeks FROM permit WHERE id = ?),
                  cycle_anchor = (SELECT cycle_anchor FROM permit WHERE id = ?)
WHERE id = ?`, srcID, srcID, dstID); err != nil {
		return 0, err
	}
	ores, err := tx.ExecContext(ctx, `
INSERT INTO override (permit_id, vehicle_id, registration, state, starts_at, ends_at, created_by, created_at, empty)
SELECT ?, vehicle_id, registration, state, starts_at, ends_at, created_by, created_at, empty
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

// ---- Roster cycle weeks ----
//
// The cycle grows and shrinks only at its end (a week keeps its position and
// number for life), and every operation moves the rule rows, the week count and
// the anchor in ONE transaction: a crash between them would leave WeekAt
// pointing at rules that don't exist. The anchor string is computed by the
// caller (model.ReanchoredCycle needs the permit's timezone, which the store
// does not know).

// GrowCycle lengthens a permit's roster cycle to `to` weeks. Each new week is
// seeded with a copy of the week one cycle earlier (week 3 from week 1, week 4
// from week 2; week 2 from week 1), so the roster repeats as it did and the
// resolved car is unchanged until a new week is edited. Returns the new week
// count; refused when `to` is not longer or exceeds model.MaxCycleWeeks.
func (s *Store) GrowCycle(ctx context.Context, owner string, permitID int64, anchor string, to int) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	weeks, err := cycleWeeksTx(ctx, tx, owner, permitID)
	if err != nil {
		return 0, err
	}
	if to <= weeks || to > model.MaxCycleWeeks {
		return weeks, ErrCycleWeek
	}
	for k := weeks; k < to; k++ {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO weekly_rule (permit_id, cycle_week, weekday, vehicle_id, empty)
SELECT permit_id, ?, weekday, vehicle_id, empty FROM weekly_rule WHERE permit_id = ? AND cycle_week = ?`,
			k, permitID, k-weeks); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE permit SET cycle_weeks = ?, cycle_anchor = ? WHERE id = ?`,
		to, anchor, permitID); err != nil {
		return 0, err
	}
	return to, tx.Commit()
}

// ShrinkCycle shortens a permit's roster cycle to `to` weeks, taking the last
// weeks off and returning their rules, with their week indices (the caller
// renders them into a stateless Undo). Shrinking to one week clears the
// anchor: a plain weekly roster has no cycle.
func (s *Store) ShrinkCycle(ctx context.Context, owner string, permitID int64, anchor string, to int) (removed []model.WeeklyRule, newWeeks int, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	weeks, err := cycleWeeksTx(ctx, tx, owner, permitID)
	if err != nil {
		return nil, 0, err
	}
	if to < 1 || to >= weeks {
		return nil, weeks, ErrCycleWeek
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT id, permit_id, cycle_week, weekday, vehicle_id, empty FROM weekly_rule
WHERE permit_id = ? AND cycle_week >= ? ORDER BY cycle_week, weekday`, permitID, to)
	if err != nil {
		return nil, 0, err
	}
	for rows.Next() {
		var r model.WeeklyRule
		var wd int
		var vid sql.NullInt64
		if err := rows.Scan(&r.ID, &r.PermitID, &r.Week, &wd, &vid, &r.Empty); err != nil {
			rows.Close()
			return nil, 0, err
		}
		r.Weekday = time.Weekday(wd)
		r.VehicleID = vid.Int64 // 0 when NULL (a clear day)
		removed = append(removed, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM weekly_rule WHERE permit_id = ? AND cycle_week >= ?`, permitID, to); err != nil {
		return nil, 0, err
	}
	if to == 1 {
		anchor = "" // back to a plain weekly roster
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE permit SET cycle_weeks = ?, cycle_anchor = ? WHERE id = ?`, to, anchor, permitID); err != nil {
		return nil, 0, err
	}
	return removed, to, tx.Commit()
}

// RestoreCycle is ShrinkCycle's undo: it lengthens the cycle back to `to`
// weeks and re-inserts the removed rules at their own week indices. Rules are
// inserted fresh (new ids); the caller has validated vehicle ownership and
// that every rule's week lies in the weeks being restored.
func (s *Store) RestoreCycle(ctx context.Context, owner string, permitID int64, rules []model.WeeklyRule, anchor string, to int) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	weeks, err := cycleWeeksTx(ctx, tx, owner, permitID)
	if err != nil {
		return 0, err
	}
	if to <= weeks || to > model.MaxCycleWeeks {
		return weeks, ErrCycleWeek
	}
	for _, r := range rules {
		if r.Week < weeks || r.Week >= to {
			return weeks, ErrCycleWeek
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO weekly_rule (permit_id, cycle_week, weekday, vehicle_id, empty) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(permit_id, cycle_week, weekday) DO UPDATE SET vehicle_id = excluded.vehicle_id, empty = excluded.empty`,
			permitID, r.Week, int(r.Weekday), nullableVehicle(r), r.Empty); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE permit SET cycle_weeks = ?, cycle_anchor = ? WHERE id = ?`,
		to, anchor, permitID); err != nil {
		return 0, err
	}
	return to, tx.Commit()
}

// cycleWeeksTx reads the owner's permit's cycle length inside tx (at least 1).
func cycleWeeksTx(ctx context.Context, tx *sql.Tx, owner string, permitID int64) (int, error) {
	var weeks int
	if err := tx.QueryRowContext(ctx,
		`SELECT cycle_weeks FROM permit WHERE id = ? AND owner = ?`, permitID, owner).Scan(&weeks); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if weeks < 1 {
		weeks = 1
	}
	return weeks, nil
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
func (s *Store) CreateOverrideCapped(ctx context.Context, permitID, vehicleID int64, registration, state string, startsAt time.Time, endsAt *time.Time, createdBy string, limit int) (int64, error) {
	if vehicleID == 0 && registration == "" {
		return 0, errors.New("store: a booking needs a vehicle or a plate; use CreateEmptyOverride to leave the permit empty")
	}
	return s.createOverrideCapped(ctx, permitID, vehicleID, registration, state, startsAt, endsAt, createdBy, limit, false)
}

// CreateEmptyOverride books the permit to have no rego on it for the window:
// the one booking shape with neither a vehicle nor a plate.
func (s *Store) CreateEmptyOverride(ctx context.Context, permitID int64, startsAt time.Time, endsAt *time.Time, createdBy string, limit int) (int64, error) {
	return s.createOverrideCapped(ctx, permitID, 0, "", "", startsAt, endsAt, createdBy, limit, true)
}

func (s *Store) createOverrideCapped(ctx context.Context, permitID, vehicleID int64, registration, state string, startsAt time.Time, endsAt *time.Time, createdBy string, limit int, empty bool) (int64, error) {
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
		state = "" // a saved-vehicle override takes its state from the vehicle, not the row
	}
	res, err := tx.ExecContext(ctx, `
INSERT INTO override (permit_id, vehicle_id, registration, state, starts_at, ends_at, created_by, created_at, guest_token_id, empty)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		permitID, vid, registration, state, startsAt.UTC().Format(time.RFC3339), endsAtSQL(endsAt), createdBy, nowUTC(), empty)
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
	return s.createOverrideGuarded(ctx, permitID, vehicleID, "", "", startsAt, endsAt, createdBy, guestTokenID)
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
func (s *Store) createOverrideGuarded(ctx context.Context, permitID, vehicleID int64, registration, state string, startsAt time.Time, endsAt *time.Time, createdBy string, guestTokenID int64) (int64, error) {
	var vid any // NULL for a plate booking
	if vehicleID != 0 {
		vid = vehicleID
		state = "" // a saved-vehicle override takes its state from the vehicle, not the row
	}
	// The liveness EXISTS applies ONLY to real guest creates: guest_token_id 0 is a
	// member-created override (CreateOverride delegates here), which has no token to
	// check and must not be refused by one. It asks the same three questions as
	// GuestOverrideStillAuthorised — token revoked, grant disabled, and the account's
	// guest kill-switch — so that a pause-all lands here the way a revoke does. It
	// used to skip the kill-switch, so an approval while passes were paused wrote the
	// row, marked the request approved, and only then had the apply refuse it: the
	// household saw an "approved" request with nothing behind it. The overall cap applies to both. The GUEST
	// sub-cap (last clause) applies only to guest creates: it counts just guest rows
	// against a smaller ceiling so a link holder cycling plates cannot fill the whole
	// per-permit budget and lock the household out of booking their OWN permit — the
	// owner path (CreateOverrideCapped) counts all rows against the larger overall cap,
	// so the sub-cap always leaves room for the owner.
	res, err := s.db.ExecContext(ctx, `
INSERT INTO override (permit_id, vehicle_id, registration, state, starts_at, ends_at, created_by, created_at, guest_token_id)
SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
WHERE (? = 0 OR EXISTS (
        SELECT 1 FROM guest_token t JOIN guest_grant g ON g.id = t.grant_id
        WHERE t.id = ? AND t.revoked_at = '' AND g.enabled = 1
          AND COALESCE((SELECT guests_enabled FROM account_flags WHERE owner = g.owner), 1) = 1))
  AND (SELECT COUNT(*) FROM override
       WHERE permit_id = ? AND (ends_at IS NULL OR ends_at > ?)) < ?
  AND (? = 0 OR (SELECT COUNT(*) FROM override
       WHERE permit_id = ? AND guest_token_id != 0 AND (ends_at IS NULL OR ends_at > ?)) < ?)`,
		permitID, vid, registration, state, startsAt.UTC().Format(time.RFC3339), endsAtSQL(endsAt), createdBy, nowUTC(), guestTokenID,
		guestTokenID, guestTokenID, permitID, nowUTC(), MaxLiveOverridesPerPermit,
		guestTokenID, permitID, nowUTC(), MaxLiveGuestOverridesPerPermit)
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
// override cap. The caller must NOT go on to change the plate at the tenant.
var ErrGuestOverrideRefused = errors.New("store: guest link is no longer active, or the permit has too many live bookings")

// MaxLiveOverridesPerPermit caps simultaneously-active bookings on one permit so the
// never-pruned, hot-path override table cannot grow without bound. It applies to guest
// creates as well as member ones — capping only the member path left the public guest
// and door-QR flows able to insert without limit, which is the larger surface.
const MaxLiveOverridesPerPermit = 50

// MaxLiveGuestOverridesPerPermit sub-caps how many live overrides GUEST links (and the
// public door QR) may hold on one permit at once. It is deliberately well below
// MaxLiveOverridesPerPermit so anonymous/guest traffic — which is the untrusted, higher-
// volume surface — can never consume the whole per-permit budget and leave the owner
// unable to book their own permit (the owner path counts against the larger cap). Plenty
// for legitimate use, where a guest activation is a single row.
const MaxLiveGuestOverridesPerPermit = 20

// CreatePlateOverride books a one-off using a literal, unsaved number plate
// (vehicle_id IS NULL). The plate is normalised by the caller.
func (s *Store) CreatePlateOverride(ctx context.Context, permitID int64, registration, state string, startsAt time.Time, endsAt *time.Time, createdBy string) (int64, error) {
	return s.CreateGuestPlateOverride(ctx, permitID, registration, state, startsAt, endsAt, createdBy, 0)
}

// CreateGuestPlateOverride is CreatePlateOverride tagged with the guest link
// that made it (see CreateGuestOverride). state is the plate's registration state
// code ("" = the tenant's home state).
func (s *Store) CreateGuestPlateOverride(ctx context.Context, permitID int64, registration, state string, startsAt time.Time, endsAt *time.Time, createdBy string, guestTokenID int64) (int64, error) {
	return s.createOverrideGuarded(ctx, permitID, 0, registration, state, startsAt, endsAt, createdBy, guestTokenID)
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

// nullableVehicle is a rule's vehicle_id as SQL: NULL for an empty day.
func nullableVehicle(r model.WeeklyRule) any {
	if r.Empty || r.VehicleID == 0 {
		return nil
	}
	return r.VehicleID
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
SELECT id, permit_id, vehicle_id, registration, state, starts_at, ends_at, created_by, created_at, guest_token_id, empty
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
		if err := rows.Scan(&o.ID, &o.PermitID, &vid, &o.Registration, &o.State, &starts, &ends, &o.CreatedBy, &created, &o.GuestTokenID, &o.Empty); err != nil {
			return nil, err
		}
		o.VehicleID = vid.Int64 // 0 when NULL (an ad-hoc plate, or an empty booking)
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
	// Resolve the plate THROUGH the vehicle. A guest who taps one of the link's saved
	// cars creates a vehicle-backed override (vehicle_id set, registration empty), so a
	// `registration != ''` filter made that row invisible — the revert button never
	// rendered and the resident's own plate stayed off the permit till end of day with
	// no guest-side remedy. For "tap your car" grants this was the ONLY activation path,
	// so the affordance was inert throughout. Pick the newest guest override regardless
	// of kind and read its plate from the join when the row carries no literal one.
	var reg string
	err := s.db.QueryRowContext(ctx, `
SELECT COALESCE(NULLIF(o.registration, ''), v.registration, '')
FROM override o
LEFT JOIN vehicle v ON v.id = o.vehicle_id
WHERE o.permit_id = ? AND o.guest_token_id = ?
  AND o.starts_at <= ? AND (o.ends_at IS NULL OR o.ends_at > ?)
ORDER BY o.created_at DESC, o.id DESC LIMIT 1`,
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
	res, err := s.db.ExecContext(ctx, `
DELETE FROM override
WHERE id = ? AND permit_id IN (SELECT id FROM permit WHERE owner = ?)`, id, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
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
// The guarded insert proves all that at INSERT time, but the tenant write happens
// seconds later, and an owner can revoke or EDIT the pass in between (removing the very
// vehicle the guest picked). Called under the permit apply claim immediately before the
// tenant write.
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
        AND (EXISTS (SELECT 1 FROM guest_grant_vehicle gv
                     WHERE gv.grant_id = g.id AND gv.vehicle_id = o.vehicle_id)
             OR (g.all_vehicles = 1
                 AND EXISTS (SELECT 1 FROM vehicle v WHERE v.id = o.vehicle_id AND v.owner = g.owner))))
    OR (o.vehicle_id IS NULL AND g.allow_plate = 1))`,
		overrideID, guestTokenID).Scan(&n)
	return n > 0, err
}

// GuestTokenStillLive reports whether a guest link still carries any authority at all:
// unrevoked token, enabled grant, account switch on. Used before a tenant write that
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
