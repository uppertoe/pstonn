package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
)

// PickerGrant is the household's own quick picker: a guest grant whose single
// link the household keeps for itself, saved to a phone's home screen. It is the
// guest-pass machinery pointed back at the account — the same activation page,
// the same end-of-day booking, the same revocation sweeps — with three
// differences the public page reads off Grant.Picker: the household's regos show
// in full, the heading names the permit, and there is no one to notify.
//
// The raw token is sealed at rest (as a printed QR's is) so the SAME link can be
// shown again on every visit to the Guests tab. One per account.
type PickerGrant struct {
	GrantID        int64
	PermitID       int64
	AllowOvernight bool
	TokenID        int64
	TokenSealed    string
	CreatedAt      time.Time
	Vehicles       []model.Vehicle
}

// CreatePickerGrant mints the account's quick picker: the grant, its allowed
// regos and one sealed token, in a transaction. Every rego must belong to owner
// and the permit must be theirs (ErrNotFound otherwise); a second picker is
// refused with ErrDuplicate so a double-submitted form cannot leave two live links.
func (s *Store) CreatePickerGrant(ctx context.Context, owner, createdBy string, permitID int64, allowOvernight bool, vehicleIDs []int64, tokenHash, tokenSealed string) (int64, error) {
	if len(vehicleIDs) == 0 {
		return 0, ErrNotFound
	}
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
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM guest_grant WHERE owner = ? AND picker = 1`, owner).Scan(&existing); err != nil {
		return 0, err
	}
	if existing > 0 {
		return 0, ErrDuplicate
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO guest_grant (owner, permit_id, label, allow_overnight, allow_plate, on_screen, request_only, picker, enabled, created_at, created_by)
		 VALUES (?, ?, 'Quick picker', ?, 0, 0, 0, 1, 1, ?, ?)`,
		owner, permitID, boolInt(allowOvernight), nowUTC(), createdBy)
	if err != nil {
		return 0, err
	}
	grantID, err := res.LastInsertId()
	if err != nil {
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
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO guest_token (grant_id, recipient_email, token_hash, token_sealed, created_at) VALUES (?, '', ?, ?, ?)`,
		grantID, tokenHash, tokenSealed, nowUTC()); err != nil {
		return 0, err
	}
	return grantID, tx.Commit()
}

// PickerGrant returns the account's quick picker with its regos and sealed
// token, or ErrNotFound when none has been made.
func (s *Store) PickerGrant(ctx context.Context, owner string) (PickerGrant, error) {
	var g PickerGrant
	var overnight int
	var created string
	err := s.db.QueryRowContext(ctx, `
SELECT g.id, g.permit_id, g.allow_overnight, t.id, t.token_sealed, g.created_at
FROM guest_grant g
JOIN guest_token t ON t.grant_id = g.id AND t.revoked_at = ''
WHERE g.owner = ? AND g.picker = 1 AND g.enabled = 1
ORDER BY t.id DESC LIMIT 1`, owner).
		Scan(&g.GrantID, &g.PermitID, &overnight, &g.TokenID, &g.TokenSealed, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return PickerGrant{}, ErrNotFound
	}
	if err != nil {
		return PickerGrant{}, err
	}
	g.AllowOvernight = overnight == 1
	g.CreatedAt, _ = time.Parse(time.RFC3339, created)
	g.Vehicles, err = s.queryVehicles(ctx, `
SELECT v.id, v.registration, v.label, v.email, v.color, v.state, v.notify_driver FROM vehicle v
JOIN guest_grant_vehicle gv ON gv.vehicle_id = v.id
WHERE gv.grant_id = ? ORDER BY v.label, v.registration`, g.GrantID)
	return g, err
}

// RotatePickerToken gives the picker a new link and kills the old one. The
// token ROW is kept and rebound, for the reason ResetGuestToken spells out: a
// booking the old link already made keeps running (the household chose it, and a
// lost phone is not a decision to take their own car off the permit), and
// keeping the row id is what keeps that booking reachable by the sweeps that
// join guest_token. Owner-scoped; ErrNotFound if the account has no picker.
func (s *Store) RotatePickerToken(ctx context.Context, owner string, newHash, newSealed string) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE guest_token SET token_hash = ?, token_sealed = ?, created_at = ?, revoked_at = '', expires_at = ''
WHERE id = (SELECT t.id FROM guest_token t JOIN guest_grant g ON g.id = t.grant_id
            WHERE g.owner = ? AND g.picker = 1 AND t.revoked_at = '' ORDER BY t.id DESC LIMIT 1)`,
		newHash, newSealed, nowUTC(), owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
