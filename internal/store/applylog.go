package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ApplyRecord is one row of the apply audit log.
type ApplyRecord struct {
	ID           int64
	PermitID     int64
	Registration string
	Source       string
	Status       string // "success" | "error" | "noop"
	Detail       string
	At           time.Time
}

// PruneApplyLog deletes apply-log rows older than before. The log otherwise
// grows by one row per apply event forever. Losing an idle permit's very last
// row only means one duplicate log entry on its next apply — harmless.
func (s *Store) PruneApplyLog(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM apply_log WHERE at < ?`, before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// LastApply returns the most recent apply-log row for a permit, or ErrNotFound.
// Used to suppress duplicate notifications when the same outcome repeats.
func (s *Store) LastApply(ctx context.Context, permitID int64) (ApplyRecord, error) {
	var a ApplyRecord
	var at string
	err := s.db.QueryRowContext(ctx, `
SELECT id, permit_id, registration, source, status, detail, at
FROM apply_log WHERE permit_id = ? ORDER BY id DESC LIMIT 1`, permitID).
		Scan(&a.ID, &a.PermitID, &a.Registration, &a.Source, &a.Status, &a.Detail, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	a.At, _ = time.Parse(time.RFC3339, at)
	return a, nil
}

func (s *Store) RecordApply(ctx context.Context, permitID int64, registration, source, status, detail string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO apply_log (permit_id, registration, source, status, detail, at)
VALUES (?, ?, ?, ?, ?, ?)`,
		permitID, registration, source, status, detail, nowUTC())
	return err
}

// ListApplyLogFor returns recent apply-log rows for the given app user's permits.
func (s *Store) ListApplyLogFor(ctx context.Context, owner string, limit int) ([]ApplyRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT a.id, a.permit_id, a.registration, a.source, a.status, a.detail, a.at
FROM apply_log a JOIN permit p ON a.permit_id = p.id
WHERE p.owner = ?
ORDER BY a.at DESC LIMIT ?`, owner, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ApplyRecord
	for rows.Next() {
		var r ApplyRecord
		var at string
		if err := rows.Scan(&r.ID, &r.PermitID, &r.Registration, &r.Source, &r.Status, &r.Detail, &at); err != nil {
			return nil, err
		}
		r.At, _ = time.Parse(time.RFC3339, at)
		out = append(out, r)
	}
	return out, rows.Err()
}
