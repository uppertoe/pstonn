package store

import (
	"context"
	"time"
)

// Change actions. Stable slugs, so the rendering layer decides the wording and
// old rows keep making sense after a copy change. Grouped by what they touch.
const (
	// Permits
	ActionPermitAdd    = "permit.add"
	ActionPermitRemove = "permit.remove"
	ActionPermitRename = "permit.rename"
	ActionScheduleCopy = "schedule.copy"
	// Weekly roster
	ActionRosterSet   = "roster.set"
	ActionRosterClear = "roster.clear"
	// One-off bookings
	ActionOverrideAdd    = "override.add"
	ActionOverrideDelete = "override.delete"
	// Vehicles
	ActionVehicleAdd    = "vehicle.add"
	ActionVehicleDelete = "vehicle.delete"
	ActionVehicleEmail  = "vehicle.email"
	// Guest access
	ActionGuestCreate  = "guest.create"
	ActionGuestUpdate  = "guest.update"
	ActionGuestDelete  = "guest.delete"
	ActionGuestRevoke  = "guest.revoke"
	ActionGuestToggle  = "guest.toggle"
	ActionDoorQRCreate = "doorqr.create"
	ActionDoorQRRevoke = "doorqr.revoke"
	ActionRequestOK    = "request.approve"
	ActionRequestNo    = "request.deny"
	// Shared access
	ActionMemberAdd    = "member.add"
	ActionMemberRemove = "member.remove"
	ActionMemberLeave  = "member.leave"
	// Council connection
	ActionCouncilLink   = "council.link"
	ActionCouncilUnlink = "council.unlink"
	ActionCouncilForget = "council.forget-password"
)

// Change is one recorded account change.
type Change struct {
	ID     int64
	Owner  string
	Actor  string
	Action string
	Target string
	Detail string
	At     time.Time
}

// RecordChange appends to the account's change log. Best-effort by design: the
// caller has already performed the change, so a logging failure must never fail
// the request — it is reported to the caller only so it can be logged.
func (s *Store) RecordChange(ctx context.Context, owner, actor, action, target, detail string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO account_log (owner, actor, action, target, detail, at) VALUES (?, ?, ?, ?, ?, ?)`,
		owner, actor, action, target, detail, nowUTC())
	return err
}

// ListChanges returns an account's most recent changes, newest first.
func (s *Store) ListChanges(ctx context.Context, owner string, limit int) ([]Change, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, owner, actor, action, target, detail, at
FROM account_log WHERE owner = ? ORDER BY id DESC LIMIT ?`, owner, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Change
	for rows.Next() {
		var c Change
		var at string
		if err := rows.Scan(&c.ID, &c.Owner, &c.Actor, &c.Action, &c.Target, &c.Detail, &at); err != nil {
			return nil, err
		}
		c.At, _ = time.Parse(time.RFC3339, at)
		out = append(out, c)
	}
	return out, rows.Err()
}

// PruneChangeLog deletes entries older than before. The log names people and
// plates, so it is kept to the same 90-day window as the apply log rather than
// forever: long enough to answer "who changed this?", short enough not to become
// an indefinite record of a household's movements.
func (s *Store) PruneChangeLog(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM account_log WHERE at < ?`, before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
