package server

import (
	"context"
	"log"

	"github.com/uppertoe/pstonn/internal/store"
)

// logChange records who changed what on an account. Call it AFTER the change has
// succeeded. Best-effort: the mutation already happened, so a logging failure is
// logged and swallowed rather than failing a request the user's data already
// reflects.
//
// This exists because notifications only fire on council apply outcomes, which
// makes configuration changes invisible: clearing a roster day produces no apply
// at all, so on a shared account there was no way to answer "who changed this?".
func (s *Server) logChange(ctx context.Context, owner, actor, action, target, detail string) {
	if err := s.store.RecordChange(ctx, owner, actor, action, target, detail); err != nil {
		log.Printf("changelog %s %s: %v", action, owner, err)
	}
}

// notifyDestructive tells the account's OTHER members that someone removed
// something irreversible — a wiped roster, a deleted car, a retired permit, a
// revoked pass. Only the destructive set, and never the person who did it: a
// notice for every roster tweak would be noise, but silence on the destructive
// ones is how a hostile member (or an honest mistake) goes unnoticed until
// someone is parked without a permit.
//
// Durable and quiet-hours-respecting: this is information, not an emergency.
func (s *Server) notifyDestructive(ctx context.Context, owner, actor, summary string) {
	if s.notify == nil {
		return
	}
	if err := s.notify.NotifyAccountChange(ctx, owner, actor, summary); err != nil {
		log.Printf("notify account change for %s: %v", owner, err)
	}
}

// plateOf resolves a vehicle id to its plate for logging, scoped to the owner so
// it can never read another account's car. "" when unknown — a log line is worth
// writing even if the plate can't be resolved.
func (s *Server) plateOf(ctx context.Context, owner string, vehicleID int64) string {
	if vehicleID == 0 {
		return ""
	}
	vs, err := s.store.ListVehiclesFor(ctx, owner)
	if err != nil {
		return ""
	}
	for _, v := range vs {
		if v.ID == vehicleID {
			return v.Registration
		}
	}
	return ""
}

// grantLabel names a guest pass for the log, scoped to the owner. Falls back to
// the permit name, then to "" — a log line is worth writing regardless.
func (s *Server) grantLabel(ctx context.Context, owner string, grantID int64) string {
	details, err := s.store.ListGuestGrants(ctx, owner)
	if err == nil {
		for _, d := range details {
			if d.Grant.ID == grantID {
				if d.Grant.Label != "" {
					return d.Grant.Label
				}
				return s.permitLabelByID(ctx, owner, d.Grant.PermitID)
			}
		}
	}
	// Printed door QRs are excluded from ListGuestGrants, so try that list too.
	if doors, derr := s.store.ListPrintedGrants(ctx, owner); derr == nil {
		for _, d := range doors {
			if d.GrantID == grantID {
				return d.PermitLabel
			}
		}
	}
	return ""
}

// permitLabelByID names one of the owner's permits for the log.
func (s *Server) permitLabelByID(ctx context.Context, owner string, permitID int64) string {
	p, err := s.store.GetPermit(ctx, permitID)
	if err != nil || p.Owner != owner {
		return ""
	}
	return permitLabel(p)
}

// changeText renders one logged change as a sentence for the Activity page. The
// store keeps stable slugs so wording can change here without rewriting history.
func changeText(c store.Change) string {
	switch c.Action {
	case store.ActionPermitAdd:
		return "started managing the permit " + c.Target
	case store.ActionPermitRemove:
		return "stopped managing the permit " + c.Target + " (its schedule and history were deleted)"
	case store.ActionPermitRename:
		return "renamed a permit to " + c.Target
	case store.ActionScheduleCopy:
		return "copied a schedule onto " + c.Target + ", replacing its roster and one-off bookings"
	case store.ActionRosterSet:
		return "set " + c.Target + " to " + c.Detail
	case store.ActionRosterClear:
		return "cleared the roster for " + c.Target
	case store.ActionOverrideAdd:
		return "added a one-off booking for " + c.Target + " (" + c.Detail + ")"
	case store.ActionOverrideDelete:
		return "cancelled a one-off booking" + optional(c.Target, " for ")
	case store.ActionVehicleAdd:
		return "added the car " + c.Target
	case store.ActionVehicleDelete:
		// Target can be empty when the plate could not be read at delete time; the
		// row is still worth writing, so degrade to "a car" rather than a gap.
		if c.Target == "" {
			return "deleted a car (any roster days and bookings using it went too)"
		}
		return "deleted the car " + c.Target + " (any roster days and bookings using it went too)"
	case store.ActionVehicleEmail:
		return "changed the driver email for " + c.Target
	case store.ActionGuestCreate:
		return "created a guest pass" + optional(c.Target, " for ")
	case store.ActionGuestUpdate:
		return "changed a guest pass" + optional(c.Target, " (") + closeParen(c.Target)
	case store.ActionGuestDelete:
		return "deleted a guest pass" + optional(c.Target, " (") + closeParen(c.Target) + " — its links stopped working"
	case store.ActionGuestRevoke:
		return "revoked a guest link" + optional(c.Target, " for ")
	case store.ActionGuestResend:
		// Re-sending ROTATES the token: the recipient's previous link dies. That is
		// a silent change to someone else's access, so it belongs in the log.
		return "re-sent a guest link" + optional(c.Target, " to ") + " — the previous link stopped working"
	case store.ActionDoorQRShow:
		return "showed the on-screen visitor QR" + optional(c.Target, " for ")
	case store.ActionGuestToggle:
		if c.Detail == "off" {
			return "paused all guest passes"
		}
		return "resumed guest passes"
	case store.ActionDoorQRCreate:
		return "created a printed door QR for " + c.Target
	case store.ActionDoorQRRevoke:
		return "removed a printed door QR" + optional(c.Target, " for ") + " — any printed copy stopped working"
	case store.ActionRequestOK:
		return "approved a visitor's request for " + c.Target
	case store.ActionRequestNo:
		// The deny path does not fetch the plate, so this is usually empty.
		if c.Target == "" {
			return "declined a visitor's request"
		}
		return "declined a visitor's request for " + c.Target
	case store.ActionMemberAdd:
		return "gave " + c.Target + " shared access"
	case store.ActionMemberRemove:
		return "removed " + c.Target + "'s shared access" + optional(c.Detail, " (") + closeParen(c.Detail)
	case store.ActionMemberLeave:
		return "left this shared account"
	case store.ActionCouncilLink:
		return "connected the council account"
	case store.ActionCouncilUnlink:
		return "disconnected the council account"
	case store.ActionCouncilForget:
		return "turned off automatic reconnection"
	default:
		// Unknown slug (an older row, a newer binary): show something rather than
		// dropping the entry, since the point of the log is completeness.
		return c.Action + optional(c.Target, " ")
	}
}

func optional(s, prefix string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}

// closeParen closes a parenthesis that optional() opened, and nothing otherwise.
func closeParen(s string) string {
	if s == "" {
		return ""
	}
	return ")"
}
