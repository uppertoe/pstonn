package store

import (
	"context"

	"github.com/uppertoe/pstonn/internal/model"
)

// ---- Vehicles ----

// ListVehicles returns every vehicle across all owners (used by the scheduler to
// map vehicle IDs to registrations for permits it reconciles).
func (s *Store) ListVehicles(ctx context.Context) ([]model.Vehicle, error) {
	return s.queryVehicles(ctx, `SELECT id, registration, label, email, color FROM vehicle ORDER BY label, registration`)
}

// VehicleRef is a vehicle plus its owner, used by the scheduler to resolve a
// permit's scheduled vehicle_id ONLY against vehicles owned by that permit's
// owner (defence-in-depth against a rule/override that references a foreign id).
type VehicleRef struct {
	ID           int64
	Owner        string
	Registration string
	Label        string
	Email        string
}

// ListVehicleRefs returns every vehicle with its owner, for owner-scoped
// resolution in the scheduler.
func (s *Store) ListVehicleRefs(ctx context.Context) ([]VehicleRef, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, owner, registration, label, email FROM vehicle`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VehicleRef
	for rows.Next() {
		var v VehicleRef
		if err := rows.Scan(&v.ID, &v.Owner, &v.Registration, &v.Label, &v.Email); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// VehicleOwnedBy reports whether vehicle id exists and belongs to owner. Used to
// reject a rule/override that points at another user's vehicle (IDOR guard).
func (s *Store) VehicleOwnedBy(ctx context.Context, owner string, id int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM vehicle WHERE id = ? AND owner = ?`, id, owner).Scan(&n)
	return n > 0, err
}

// ListVehiclesFor returns the vehicles owned by one app user.
func (s *Store) ListVehiclesFor(ctx context.Context, owner string) ([]model.Vehicle, error) {
	return s.queryVehicles(ctx,
		`SELECT id, registration, label, email, color FROM vehicle WHERE owner = ? ORDER BY label, registration`, owner)
}

func (s *Store) queryVehicles(ctx context.Context, query string, args ...any) ([]model.Vehicle, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Vehicle
	for rows.Next() {
		var v model.Vehicle
		if err := rows.Scan(&v.ID, &v.Registration, &v.Label, &v.Email, &v.Color); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// vehiclePalette is a small, accessible categorical palette. A vehicle's colour
// is assigned ONCE at creation and stored, so the same car reads identically
// everywhere and adding/removing other cars never re-colours it.
var vehiclePalette = []string{
	"#2f6feb", "#127a49", "#b54708", "#7a5af8",
	"#0e7490", "#be185d", "#4d7c0f", "#9333ea",
}

// pickVehicleColor returns the first palette colour not already used by this
// owner, so a household's cars stay visually distinct; once the palette is
// exhausted it wraps by count (unavoidable collision, but stable).
func pickVehicleColor(used map[string]bool) string {
	for _, c := range vehiclePalette {
		if !used[c] {
			return c
		}
	}
	return vehiclePalette[len(used)%len(vehiclePalette)]
}

func (s *Store) CreateVehicle(ctx context.Context, owner, registration, label string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Assign a stable colour: the first palette entry this owner isn't using yet.
	used := map[string]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT color FROM vehicle WHERE owner = ? AND color != ''`, owner)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			return 0, err
		}
		used[c] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO vehicle (owner, registration, label, color, created_at) VALUES (?, ?, ?, ?, ?)`,
		owner, registration, label, pickVehicleColor(used), nowUTC())
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrDuplicate
		}
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// BackfillVehicleColors assigns a stored colour to any vehicle still missing one
// (pre-migration rows), preserving each owner's CURRENT on-screen colours: it
// walks their vehicles in the same order the UI lists them (label, registration)
// and hands out palette colours in that order. Idempotent — a no-op once done.
func (s *Store) BackfillVehicleColors(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, owner FROM vehicle WHERE color = '' ORDER BY owner, label, registration`)
	if err != nil {
		return err
	}
	type ov struct {
		id    int64
		owner string
	}
	var todo []ov
	for rows.Next() {
		var r ov
		if err := rows.Scan(&r.id, &r.owner); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	i, prev := 0, ""
	for _, r := range todo {
		if r.owner != prev {
			i, prev = 0, r.owner
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE vehicle SET color = ? WHERE id = ?`,
			vehiclePalette[i%len(vehiclePalette)], r.id); err != nil {
			return err
		}
		i++
	}
	return nil
}

// SetVehicleEmail sets (or clears) the optional driver email on a vehicle,
// scoped to its owner.
func (s *Store) SetVehicleEmail(ctx context.Context, owner string, id int64, email string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE vehicle SET email = ? WHERE id = ? AND owner = ?`, email, id, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteVehicle removes a vehicle, scoped to its owner (so one user cannot delete
// another's vehicle by guessing an id).
func (s *Store) DeleteVehicle(ctx context.Context, owner string, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM vehicle WHERE id = ? AND owner = ?`, id, owner)
	return err
}
