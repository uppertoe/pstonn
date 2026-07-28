package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
)

// ---- Permits ----

// ListPermits returns every permit across all owners (used by the scheduler,
// which reconciles each permit using its owner's council session).
func (s *Store) ListPermits(ctx context.Context) ([]model.Permit, error) {
	return s.queryPermits(ctx,
		`SELECT `+permitCols+` FROM permit ORDER BY label, council_permit_id`)
}

// ListPermitsFor returns the permits owned by one app user.
func (s *Store) ListPermitsFor(ctx context.Context, owner string) ([]model.Permit, error) {
	return s.queryPermits(ctx,
		`SELECT `+permitCols+` FROM permit WHERE owner = ? ORDER BY label, council_permit_id`, owner)
}

// permitCols is the column list backing scanPermit; keep the two in lockstep.
const permitCols = `id, owner, council_permit_id, permit_type_id, label, active_registration, end_date, status, expiry_reminded, permit_number, permit_type, fail_streak`

// scanPermit reads one permit row (permitCols order), parsing the stored strings.
func scanPermit(sc interface{ Scan(...any) error }) (model.Permit, error) {
	var p model.Permit
	var endDate, reminded string
	err := sc.Scan(&p.ID, &p.Owner, &p.CouncilPermitID, &p.PermitTypeID, &p.Label,
		&p.ActiveRegistration, &endDate, &p.Status, &reminded, &p.PermitNumber, &p.PermitType,
		&p.FailStreak)
	if err != nil {
		return p, err
	}
	if endDate != "" {
		p.EndDate, _ = time.Parse(time.RFC3339, endDate)
	}
	p.ExpiryReminded = reminded == "1"
	return p, nil
}

func (s *Store) queryPermits(ctx context.Context, query string, args ...any) ([]model.Permit, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Permit
	for rows.Next() {
		p, err := scanPermit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetPermit(ctx context.Context, id int64) (model.Permit, error) {
	p, err := scanPermit(s.db.QueryRowContext(ctx,
		`SELECT `+permitCols+` FROM permit WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// PermitByCouncilID looks up a permit by its globally-unique council permit id,
// so a caller can check whether it is already managed (and by whom) before
// claiming it. Returns ErrNotFound when no row exists.
func (s *Store) PermitByCouncilID(ctx context.Context, councilPermitID string) (model.Permit, error) {
	p, err := scanPermit(s.db.QueryRowContext(ctx,
		`SELECT `+permitCols+` FROM permit WHERE council_permit_id = ?`, councilPermitID))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// UpsertPermit inserts a permit, or refreshes the type of one the SAME owner
// already holds. It never reassigns ownership: the ON CONFLICT update is guarded
// by owner, so one user can never take over another user's permit row by
// re-submitting its council permit id. Callers must confirm the permit belongs
// to the owner's council account first (see addPermit); this is the last line of
// defence. The label is only set on first insert — re-adding a permit keeps any
// name the user has since chosen (see SetPermitLabel). Returns the row id.
func (s *Store) UpsertPermit(ctx context.Context, owner, councilPermitID, permitTypeID, label string) (int64, error) {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO permit (owner, council_permit_id, permit_type_id, label, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(council_permit_id) DO UPDATE SET
    permit_type_id = excluded.permit_type_id,
    updated_at     = excluded.updated_at
WHERE permit.owner = excluded.owner`,
		owner, councilPermitID, permitTypeID, label, nowUTC())
	if err != nil {
		return 0, err
	}
	// Owner-scoped follow-up: when the guarded upsert no-ops because ANOTHER
	// account holds this council permit, the unscoped select would hand back the
	// foreign row id as a success — a landmine for any caller that then writes
	// through it (the handler pre-checks, but a check/upsert race gets here).
	var id int64
	err = s.db.QueryRowContext(ctx,
		`SELECT id FROM permit WHERE council_permit_id = ? AND owner = ?`, councilPermitID, owner).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrDuplicate // held by another account
	}
	return id, err
}

// UpdatePermitMeta writes the expiry and status pulled from the council record.
// If the expiry date changes (a renewal, or a first read), the expiry-reminded
// flag is cleared so the approaching-expiry reminder re-arms for the new date.
// Owner-scoped and a no-op if the permit isn't the owner's.
func (s *Store) UpdatePermitMeta(ctx context.Context, owner, councilPermitID, status, permitNumber, permitType string, endDate time.Time) error {
	var ed string
	if !endDate.IsZero() {
		ed = endDate.UTC().Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE permit
SET status = ?, end_date = ?, permit_number = ?, permit_type = ?,
    expiry_reminded = CASE WHEN end_date = ? THEN expiry_reminded ELSE '' END,
    updated_at = ?
WHERE council_permit_id = ? AND owner = ?`,
		status, ed, permitNumber, permitType, ed, nowUTC(), councilPermitID, owner)
	return err
}

// MarkPermitExpiryReminded records that an approaching-expiry reminder has gone
// out for the permit's current end date, so it isn't sent again until the date
// changes (see UpdatePermitMeta, which clears the flag on renewal).
func (s *Store) MarkPermitExpiryReminded(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE permit SET expiry_reminded = '1' WHERE id = ?`, id)
	return err
}

// SetPermitLabel renames a permit (owner-scoped) to a name the user chooses, shown
// everywhere the permit appears. Returns ErrNotFound if it isn't the owner's.
func (s *Store) SetPermitLabel(ctx context.Context, owner string, id int64, label string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE permit SET label = ?, updated_at = ? WHERE id = ? AND owner = ?`,
		label, nowUTC(), id, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// BumpFailStreak increments a permit's consecutive-failure counter (persisted so
// a restart doesn't reset the grace window before a failure is escalated) and
// returns the new value. ClearFailStreak resets it after a success.
func (s *Store) BumpFailStreak(ctx context.Context, id int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`UPDATE permit SET fail_streak = fail_streak + 1 WHERE id = ? RETURNING fail_streak`, id).Scan(&n)
	return n, err
}

func (s *Store) ClearFailStreak(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE permit SET fail_streak = 0 WHERE id = ? AND fail_streak != 0`, id)
	return err
}

func (s *Store) SetPermitActive(ctx context.Context, id int64, registration string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE permit SET active_registration = ?, updated_at = ? WHERE id = ?`,
		registration, nowUTC(), id)
	return err
}

// DeletePermit stops administering one permit: it removes the permit row (its
// weekly_rule + override schedule cascade via ON DELETE CASCADE) plus the
// apply-log history and notify bookkeeping, neither of which has an FK cascade.
// Scoped to owner, and returns ErrNotFound if no such permit belongs to them, so
// a member can only remove a permit their own account manages. The council
// permit itself is untouched — p.stonn simply stops changing its plate.
func (s *Store) DeletePermit(ctx context.Context, id int64, owner string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM permit WHERE id = ? AND owner = ?`, id, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM apply_log WHERE permit_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM permit_notify WHERE permit_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}
