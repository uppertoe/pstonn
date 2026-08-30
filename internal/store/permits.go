package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
)

// ---- Permits ----

// permitSchemaOnce guards the lazy ADD COLUMN in ensurePermitSchema, one
// sync.Once per *Store (tests open many stores per process).
var permitSchemaOnce sync.Map // *Store -> *sync.Once

// ensurePermitSchema adds permit.active_confirmed_at to a database that
// predates it, once per open store. The proper home for this is the tolerant
// ALTER list in migrate.go (and rebuildPermitTable's column list); it lives here
// so the permit code is self-contained until that line lands — every permit
// method runs it before touching the table, so a pre-column database never
// sees "no such column: active_confirmed_at". Idempotent-by-tolerance the same
// way migrate.go's loop is: SQLite reports a duplicate column as a generic
// SQLITE_ERROR, so the message text is the only key.
//
// It must run BEFORE a method opens a rows cursor or a transaction: the pool
// holds one connection, so an Exec issued mid-iteration blocks forever.
func (s *Store) ensurePermitSchema() error {
	v, _ := permitSchemaOnce.LoadOrStore(s, &sync.Once{})
	var err error
	v.(*sync.Once).Do(func() {
		_, err = s.db.Exec(`ALTER TABLE permit ADD COLUMN active_confirmed_at TEXT NOT NULL DEFAULT ''`)
		if err != nil && strings.Contains(err.Error(), "duplicate column") {
			err = nil
		}
		if err != nil {
			err = fmt.Errorf("ensure permit.active_confirmed_at: %w", err)
			permitSchemaOnce.Delete(s) // let the next call retry rather than stay broken
		}
	})
	return err
}

// ListPermits returns every permit across all owners (used by the scheduler,
// which reconciles each permit using its owner's tenant session).
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
const permitCols = `id, owner, council_id, council_permit_id, permit_type_id, label, active_registration, end_date, status, expiry_reminded, permit_number, permit_type, fail_streak, copy_offer_done, active_confirmed_at`

// scanPermit reads one permit row (permitCols order), parsing the stored strings.
func scanPermit(sc interface{ Scan(...any) error }) (model.Permit, error) {
	var p model.Permit
	var endDate, reminded, confirmedAt string
	var copyDone int
	err := sc.Scan(&p.ID, &p.Owner, &p.TenantID, &p.CouncilPermitID, &p.PermitTypeID, &p.Label,
		&p.ActiveRegistration, &endDate, &p.Status, &reminded, &p.PermitNumber, &p.PermitType,
		&p.FailStreak, &copyDone, &confirmedAt)
	if err != nil {
		return p, err
	}
	if endDate != "" {
		p.EndDate, _ = time.Parse(time.RFC3339, endDate)
	}
	if confirmedAt != "" {
		p.ActiveConfirmedAt, _ = time.Parse(time.RFC3339, confirmedAt)
	}
	p.ExpiryReminded = reminded == "1"
	p.CopyOfferDone = copyDone == 1
	return p, nil
}

func (s *Store) queryPermits(ctx context.Context, query string, args ...any) ([]model.Permit, error) {
	if err := s.ensurePermitSchema(); err != nil {
		return nil, err
	}
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
	if err := s.ensurePermitSchema(); err != nil {
		return model.Permit{}, err
	}
	p, err := scanPermit(s.db.QueryRowContext(ctx,
		`SELECT `+permitCols+` FROM permit WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// PermitInTenant looks a permit up by the tenant's own id WITHIN one tenant —
// the lookup a handler must use, since two registry' id spaces overlap.
func (s *Store) PermitInTenant(ctx context.Context, tenantID, tenantPermitID string) (model.Permit, error) {
	if err := s.ensurePermitSchema(); err != nil {
		return model.Permit{}, err
	}
	p, err := scanPermit(s.db.QueryRowContext(ctx,
		`SELECT `+permitCols+` FROM permit WHERE council_id = ? AND council_permit_id = ?`, tenantID, tenantPermitID))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// UpsertPermit inserts a permit, or refreshes the type of one the SAME owner
// already holds. It never reassigns ownership: the ON CONFLICT update is guarded
// by owner, so one user can never take over another user's permit row by
// re-submitting its tenant permit id. Callers must confirm the permit belongs
// to the owner's tenant account first (see addPermit); this is the last line of
// defence. The label is only set on first insert — re-adding a permit keeps any
// name the user has since chosen (see SetPermitLabel). Returns the row id.
func (s *Store) UpsertPermit(ctx context.Context, owner, tenantPermitID, permitTypeID, label string) (int64, error) {
	// The permit is filed under the owner's tenant: an account belongs to exactly
	// one, so the tenant is a property of the owner, not an input a caller can get
	// wrong.
	tenantID, err := s.TenantIDFor(ctx, owner)
	if err != nil {
		return 0, err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO permit (owner, council_id, council_permit_id, permit_type_id, label, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(council_id, council_permit_id) DO UPDATE SET
    permit_type_id = excluded.permit_type_id,
    updated_at     = excluded.updated_at
WHERE permit.owner = excluded.owner`,
		owner, tenantID, tenantPermitID, permitTypeID, label, nowUTC())
	if err != nil {
		return 0, err
	}
	// Owner-scoped follow-up: when the guarded upsert no-ops because ANOTHER
	// account holds this tenant permit, the unscoped select would hand back the
	// foreign row id as a success — a landmine for any caller that then writes
	// through it (the handler pre-checks, but a check/upsert race gets here).
	var id int64
	err = s.db.QueryRowContext(ctx,
		`SELECT id FROM permit WHERE council_id = ? AND council_permit_id = ? AND owner = ?`, tenantID, tenantPermitID, owner).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrDuplicate // held by another account
	}
	return id, err
}

// UpdatePermitMeta writes the expiry and status pulled from the tenant record.
// If the expiry date changes (a renewal, or a first read), the expiry-reminded
// flag is cleared so the approaching-expiry reminder re-arms for the new date.
// Owner-scoped and a no-op if the permit isn't the owner's.
//
// Scoped by tenant as well as owner: council permit ids overlap between portals,
// so an owner linked at two councils would otherwise have both rows' status and
// expiry overwritten by whichever portal's grid was read last.
func (s *Store) UpdatePermitMeta(ctx context.Context, owner, tenantID, tenantPermitID, status, permitNumber, permitType string, endDate time.Time) error {
	var ed string
	if !endDate.IsZero() {
		ed = endDate.UTC().Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE permit
SET status = ?, end_date = ?, permit_number = ?, permit_type = ?,
    expiry_reminded = CASE WHEN end_date = ? THEN expiry_reminded ELSE '' END,
    updated_at = ?
WHERE council_permit_id = ? AND owner = ? AND council_id = ?`,
		status, ed, permitNumber, permitType, ed, nowUTC(), tenantPermitID, owner, tenantID)
	return err
}

// MarkPermitExpiryReminded records that an approaching-expiry reminder has gone
// out for the permit's current end date, so it isn't sent again until the date
// changes (see UpdatePermitMeta, which clears the flag on renewal).
// MarkCopyOfferDone retires the "renewed this permit?" copy pitch for one
// permit. One-way by design: the pitch shows once per added permit and never
// returns after a dismissal, a copy, or a first roster day.
func (s *Store) MarkCopyOfferDone(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE permit SET copy_offer_done = 1 WHERE id = ?`, id)
	return err
}

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

// SetPermitActive records the plate the council now holds on the permit, and
// stamps active_confirmed_at: every caller writes a COUNCIL-CONFIRMED plate — a
// confirmed apply (scheduler, guest, clear) or the plate read off the council's
// own list when the permit is added — so the stamp is unconditional here rather
// than a flag each caller could forget.
func (s *Store) SetPermitActive(ctx context.Context, id int64, registration string) error {
	if err := s.ensurePermitSchema(); err != nil {
		return err
	}
	now := nowUTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE permit SET active_registration = ?, active_confirmed_at = ?, updated_at = ? WHERE id = ?`,
		registration, now, now, id)
	return err
}

// TouchPermitConfirmed records that a council read taken at `at` AGREED with the
// stored plate — the common case, where nothing changes and so nothing else
// writes the stamp. Guarded on the plate (a CAS like SetPermitActiveIfUnchanged:
// a reading that took seconds must not vouch for a plate an apply committed
// meanwhile) and monotonic (never moves the stamp backwards, and a no-op when
// the reading is not newer than the stamp, so a render inside one cache window
// costs at most one write). RFC3339 UTC strings order lexically, and ” sorts
// before any of them, so the comparison is a plain string one.
func (s *Store) TouchPermitConfirmed(ctx context.Context, id int64, registration string, at time.Time) error {
	if err := s.ensurePermitSchema(); err != nil {
		return err
	}
	ts := at.UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx,
		`UPDATE permit SET active_confirmed_at = ? WHERE id = ? AND active_registration = ? AND active_confirmed_at < ?`,
		ts, id, registration, ts)
	return err
}

// DeletePermit stops administering one permit: it removes the permit row (its
// weekly_rule + override schedule cascade via ON DELETE CASCADE) plus the
// apply-log history and notify bookkeeping, neither of which has an FK cascade.
// Scoped to owner, and returns ErrNotFound if no such permit belongs to them, so
// a member can only remove a permit their own account manages. The tenant
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

// CountPermits returns how many permits are on file across all accounts. Used to
// report the rollover convergence bound at startup: the burst a shared schedule
// boundary produces scales with this number, so the guarantee is only meaningful
// stated against it.
func (s *Store) CountPermits(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM permit`).Scan(&n)
	return n, err
}

// SetPermitActiveIfUnchanged records the plate the permit now holds, but ONLY if our
// belief has not moved since `from` was read. Returns whether the write landed.
//
// For adopting a COUNCIL READING (drift, the dashboard's cached plate): those reads
// take seconds and run outside the per-permit apply claim, so a guest or reconcile
// apply can commit a newer plate while one is in flight. A blind write then regresses
// the local belief to a value the tenant no longer holds — costing a spurious
// "changed at the portal" row, a duplicate "updated" notice, and a needless tenant
// round trip before it heals. A compare-and-swap discards the stale read instead, and
// unlike taking the apply claim it holds no lock across the network call.
//
// The adopted plate is a council reading, so active_confirmed_at is stamped with it.
func (s *Store) SetPermitActiveIfUnchanged(ctx context.Context, id int64, from, to string) (bool, error) {
	if err := s.ensurePermitSchema(); err != nil {
		return false, err
	}
	now := nowUTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE permit SET active_registration = ?, active_confirmed_at = ?, updated_at = ? WHERE id = ? AND active_registration = ?`,
		to, now, now, id, from)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
