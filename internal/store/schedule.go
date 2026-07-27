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

// CreateGuestOverride is CreateOverride tagged with the guest link that made it,
// so a guest's revert can remove exactly their own changes.
func (s *Store) CreateGuestOverride(ctx context.Context, permitID, vehicleID int64, startsAt time.Time, endsAt *time.Time, createdBy string, guestTokenID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO override (permit_id, vehicle_id, registration, starts_at, ends_at, created_by, created_at, guest_token_id)
VALUES (?, ?, '', ?, ?, ?, ?, ?)`,
		permitID, vehicleID, startsAt.UTC().Format(time.RFC3339), endsAtSQL(endsAt), createdBy, nowUTC(), guestTokenID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// CreatePlateOverride books a one-off using a literal, unsaved number plate
// (vehicle_id IS NULL). The plate is normalised by the caller.
func (s *Store) CreatePlateOverride(ctx context.Context, permitID int64, registration string, startsAt time.Time, endsAt *time.Time, createdBy string) (int64, error) {
	return s.CreateGuestPlateOverride(ctx, permitID, registration, startsAt, endsAt, createdBy, 0)
}

// CreateGuestPlateOverride is CreatePlateOverride tagged with the guest link
// that made it (see CreateGuestOverride).
func (s *Store) CreateGuestPlateOverride(ctx context.Context, permitID int64, registration string, startsAt time.Time, endsAt *time.Time, createdBy string, guestTokenID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO override (permit_id, vehicle_id, registration, starts_at, ends_at, created_by, created_at, guest_token_id)
VALUES (?, NULL, ?, ?, ?, ?, ?, ?)`,
		permitID, registration, startsAt.UTC().Format(time.RFC3339), endsAtSQL(endsAt), createdBy, nowUTC(), guestTokenID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
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
