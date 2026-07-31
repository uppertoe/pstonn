package store

import (
	"context"
	"log"
	"time"

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

// vehiclePalette is a categorical palette for cars. A vehicle's colour is
// assigned ONCE and stored, so the same car reads identically everywhere and
// adding or removing other cars never re-colours it.
//
// ORDER IS THE DESIGN. pickVehicleColor takes the first unused entry, so a
// household with four cars only ever sees the first four. These are ordered
// farthest-first: each entry is the one most perceptually distant from every
// entry before it, which is what makes a short prefix maximally legible.
//
// Sixteen because a household here is not just "our two cars": it is the nanny,
// a carer, grandparents, a neighbour, a friend who visits weekly.
//
// Chosen by optimising perceptual separation (OKLab) inside a deliberately
// narrow aesthetic envelope — lightness and chroma bounded so the set reads as
// one family rather than as sixteen unrelated highlighter pens, which is what
// unconstrained maximisation produces. Every entry clears 2.7:1 against BOTH the
// light and the dark surface, because the colour is shown as a solid dot and a
// plate border on each; the plate's TEXT is always var(--ink), never the car
// colour, so these never have to carry text contrast. Minimum separation is
// roughly double the previous palette's, including under simulated deuteranopia.
var vehiclePalette = []string{
	"#b577e8", "#007914", "#a2614f", "#0081a2",
	"#b29703", "#e465a3", "#5c65d6", "#896498",
	"#e66f62", "#0c9c83", "#018ae4", "#717d07",
	"#07745d", "#1ca045", "#ba3f7f", "#6a85bd",
}

// inPalette reports whether a stored colour belongs to the CURRENT palette.
func inPalette(c string) bool {
	for _, p := range vehiclePalette {
		if p == c {
			return true
		}
	}
	return false
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

// BackfillVehicleColors gives every vehicle a colour from the CURRENT palette.
//
// It covers two cases with one pass: rows that never had a colour, and rows still
// holding a colour from a superseded palette. The second matters because colours
// are stored per car — without it, a household would keep its old colours while
// any car added later drew from the new set, so one list would show two unrelated
// palettes side by side and the "which car is this?" cue would be worse than
// before, not better.
//
// Self-guarding, so it is safe to run on every boot: an owner is only touched
// while any of their vehicles sits outside the palette, and once rewritten they
// all sit inside it. Colours are handed out in the order the UI lists them
// (label, registration) so a household's assignment is stable and reproducible.
func (s *Store) BackfillVehicleColors(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, owner, color FROM vehicle ORDER BY owner, label, registration`)
	if err != nil {
		return err
	}
	type ov struct {
		id    int64
		owner string
		color string
	}
	var all []ov
	for rows.Next() {
		var r ov
		if err := rows.Scan(&r.id, &r.owner, &r.color); err != nil {
			rows.Close()
			return err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Which owners need rewriting: any vehicle missing a colour or on an old one.
	stale := map[string]bool{}
	for _, r := range all {
		if r.color == "" || !inPalette(r.color) {
			stale[r.owner] = true
		}
	}
	if len(stale) == 0 {
		return nil
	}
	i, prev := 0, ""
	for _, r := range all {
		if !stale[r.owner] {
			continue
		}
		if r.owner != prev {
			i, prev = 0, r.owner
		}
		want := vehiclePalette[i%len(vehiclePalette)]
		i++
		if r.color == want {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE vehicle SET color = ? WHERE id = ?`, want, r.id); err != nil {
			return err
		}
	}
	log.Printf("vehicles: re-coloured %d household(s) onto the current palette", len(stale))
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

// VehiclePaletteForTest exposes the palette so a test can assert the ordering
// contract (all distinct) without making the palette itself writable.
func VehiclePaletteForTest() []string { return append([]string(nil), vehiclePalette...) }

// VehicleUsage is what a vehicle is currently holding up: which permit/weekday slots
// its roster days occupy, and how many live one-off bookings point at it.
type VehicleUsage struct {
	Rules         []VehicleRuleUse
	LiveOverrides int
}

// VehicleRuleUse is one roster day that would be emptied.
type VehicleRuleUse struct {
	PermitLabel string
	Weekday     time.Weekday
}

// VehicleUsageFor reports what deleting this vehicle would silently take with it.
//
// Deleting a car CASCADES its weekly_rule and override rows away, and a cleared day
// produces no apply, so nothing downstream notices: the permit simply keeps whatever
// plate it last had, indefinitely, with the household never told that Tuesday is now
// unscheduled. Naming the days lets the warning say which ones, so somebody can
// reassign them instead of discovering it from a parking fine.
//
// Owner-scoped, and returns nothing for a vehicle that is not theirs.
func (s *Store) VehicleUsageFor(ctx context.Context, owner string, vehicleID int64) (VehicleUsage, error) {
	var u VehicleUsage
	rows, err := s.db.QueryContext(ctx, `
SELECT COALESCE(p.label, ''), r.weekday
FROM weekly_rule r
JOIN permit p ON p.id = r.permit_id
WHERE r.vehicle_id = ? AND p.owner = ?
ORDER BY p.label, r.weekday`, vehicleID, owner)
	if err != nil {
		return u, err
	}
	for rows.Next() {
		var use VehicleRuleUse
		var wd int
		if err := rows.Scan(&use.PermitLabel, &wd); err != nil {
			rows.Close()
			return u, err
		}
		use.Weekday = time.Weekday(wd)
		u.Rules = append(u.Rules, use)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return u, err
	}
	// Only bookings that still carry authority matter; a finished one is history.
	err = s.db.QueryRowContext(ctx, `
SELECT COUNT(1) FROM override o
JOIN permit p ON p.id = o.permit_id
WHERE o.vehicle_id = ? AND p.owner = ? AND (o.ends_at IS NULL OR o.ends_at = '' OR o.ends_at > ?)`,
		vehicleID, owner, nowUTC()).Scan(&u.LiveOverrides)
	return u, err
}
