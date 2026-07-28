// Package model holds the core domain types, kept free of any persistence or
// HTTP concerns so the scheduling logic can be unit-tested in isolation.
package model

import (
	"strings"
	"time"
)

// Vehicle is a registration that may be allocated to a shared visitor permit.
type Vehicle struct {
	ID           int64
	Registration string // number plate, normalised upper-case no spaces
	Label        string // human name, e.g. "Mum's Corolla"
	Email        string // optional: who drives this car (default guest-pass recipient)
	Color        string // stable per-plate colour (hex), the at-a-glance cue
}

// Permit is a council visitor permit that holds one active vehicle at a time.
type Permit struct {
	ID                 int64
	Owner              string // app-user email that linked/owns this permit
	CouncilPermitID    string // e.g. "14423"
	PermitTypeID       string // fkPermitTypeID, e.g. "15"
	Label              string
	ActiveRegistration string    // last registration we know is allocated
	EndDate            time.Time // permit expiry from the council record (zero = unknown)
	Status             string    // council permit status, e.g. "Granted" (empty = unknown)
	ExpiryReminded     bool      // an expiry reminder has been sent for the current EndDate
	PermitNumber       string    // council permit number, e.g. "VPP24714" (empty = unknown)
	PermitType         string    // council permit type, e.g. "(A) 1st Visitor Permit"
	FailStreak         int       // consecutive failed/blocked reconcile attempts; 0 = healthy
}

// deadStatuses are the council PermitStatus WORDS that mean a permit is no longer
// usable. Matched whole-word (case-insensitive), NOT as substrings: a substring
// match would trip on live wording like "Expiring" or "Due to expire" and wrongly
// retire a still-valid permit → an un-updated plate → a fine. Expiry-by-date is
// handled separately by EndDate, so this set is really about early termination.
var deadStatuses = map[string]bool{
	"cancelled": true, "canceled": true, "cancel": true,
	"suspended": true, "suspend": true,
	"surrendered": true, "surrender": true,
	"revoked": true, "revoke": true,
	"expired": true, "lapsed": true, "closed": true, "void": true, "voided": true,
}

func deadStatus(s string) bool {
	for _, w := range strings.Fields(strings.ToLower(s)) {
		if deadStatuses[strings.Trim(w, ".,;:()[]{}\"'")] {
			return true
		}
	}
	return false
}

// Inactive reports whether a permit should no longer be actively reconciled or
// shown as a live permit: its status says it's dead, or its expiry day has fully
// passed. EndDate is treated as the INCLUSIVE last valid day in the council's
// timezone (loc): a permit is retired only once the day AFTER EndDate has begun
// there. That is deliberately conservative — the council reports zoneless local
// dates (parsed as UTC), so a plain instant compare could retire up to ~half a day
// early and cause a fine; erring late only costs a harmless doomed write. Zero end
// date + live status = active (we never retire on unknown data).
func (p Permit) Inactive(now time.Time, loc *time.Location) bool {
	if deadStatus(p.Status) {
		return true
	}
	if p.EndDate.IsZero() {
		return false
	}
	if loc == nil {
		loc = time.Local
	}
	end := p.EndDate.In(loc)
	dayAfterExpiry := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, 1)
	return !now.Before(dayAfterExpiry)
}

// WeeklyRule allocates a vehicle to a permit on a given weekday, the building
// block of a repeating roster (e.g. AVS619 on Mondays, BSD529 on Tuesdays).
type WeeklyRule struct {
	ID        int64
	PermitID  int64
	Weekday   time.Weekday
	VehicleID int64
}

// Override is a one-off allocation that takes precedence over the roster for its
// window. EndsAt == nil means "until superseded" (open-ended).
type Override struct {
	ID           int64
	PermitID     int64
	VehicleID    int64  // 0 for an ad-hoc plate (Registration set instead)
	Registration string // literal one-off plate, not a saved vehicle ("" = use VehicleID)
	StartsAt     time.Time
	EndsAt       *time.Time
	CreatedBy    string
	CreatedAt    time.Time // when it was booked; the tie-break for overlapping overrides
}

// Source identifies why a particular vehicle is the resolved allocation.
type Source string

const (
	SourceNone     Source = "none"
	SourceRoster   Source = "roster"
	SourceOverride Source = "override"
)

// Resolution is the outcome of deciding which vehicle should be active. For an
// ad-hoc one-off plate, Registration is set and VehicleID is 0.
type Resolution struct {
	VehicleID    int64
	Registration string
	Source       Source
	By           string // creator of the winning override ("" for roster/none)
}

// Resolve decides which vehicle should be allocated to a permit at time now.
// An active override wins over the weekly roster; among overlapping overrides,
// the one created most recently wins. Keying the tie-break on creation time (not
// start time) means the freshest decision takes the wheel: a guest's just-made
// activation supersedes the roster and any earlier booking for its window, while
// a later deliberate booking by the account holder still overrides the guest.
// now must already be in the timezone rosters are expressed in (weekday is read
// from it directly).
func Resolve(now time.Time, rules []WeeklyRule, overrides []Override) Resolution {
	var best *Override
	for i := range overrides {
		o := &overrides[i]
		if o.StartsAt.After(now) {
			continue // not started yet
		}
		if o.EndsAt != nil && !now.Before(*o.EndsAt) {
			continue // already ended
		}
		// Freshest decision wins. CreatedAt is only second-precision, so two
		// overrides booked in the same second tie on CreatedAt; break that by ID
		// (auto-increment → the later-inserted one), so "freshest wins" stays
		// deterministic instead of falling back to scan order.
		if best == nil || o.CreatedAt.After(best.CreatedAt) ||
			(o.CreatedAt.Equal(best.CreatedAt) && o.ID > best.ID) {
			best = o
		}
	}
	if best != nil {
		return Resolution{VehicleID: best.VehicleID, Registration: best.Registration, Source: SourceOverride, By: best.CreatedBy}
	}

	wd := now.Weekday()
	for _, r := range rules {
		if r.Weekday == wd {
			return Resolution{VehicleID: r.VehicleID, Source: SourceRoster}
		}
	}
	return Resolution{Source: SourceNone}
}

// VehicleInfo is what displaced-driver resolution needs to know about a saved
// vehicle: its plate (to match the displaced registration) and the optional
// email of whoever usually drives it.
type VehicleInfo struct {
	Registration string
	Label        string
	Email        string
}

// DisplacedBooking is the outcome of FindDisplaced. Reg == "" means no live
// third-party booking was displaced (nothing to say). Reg != "" with an empty
// Contact means a booking WAS displaced but its driver is unreachable — the
// account notification should say so, so a human can relay the warning.
type DisplacedBooking struct {
	Reg     string // the plate that lost its cover
	Contact string // email to warn ("" = nobody reachable)
}

// mailAddr extracts a usable email from an override's CreatedBy, which may
// carry an annotation ("pa@example.com (undo)") or be a non-email marker
// ("visitor (QR)"). Returns "" when no field looks like an address.
func mailAddr(createdBy string) string {
	for _, f := range strings.Fields(createdBy) {
		if strings.Contains(f, "@") {
			return f
		}
	}
	return ""
}

// FindDisplaced decides who should be warned that prevReg was just taken off a
// permit: the driver of the still-live booking that had put prevReg on, if that
// driver is a reachable third party. The contact comes from the displaced
// booking itself, never from a bare plate lookup (a plate is ambiguous; the
// booking is not): a booker who is NOT an account member (a guest who tapped
// their link is probably the person parked) wins over the saved vehicle's
// attached email (the car's usual driver — the right target when a member
// booked on the driver's behalf, or the car is borrowed). No warning goes out
// when the displaced driver is the actor who caused the displacement (they just
// swapped their own cars — compare emails, not links, so this holds across
// channels) or an account member (the account fanout already tells them).
func FindDisplaced(overrides []Override, vehicles map[int64]VehicleInfo, prevReg, actor string, members []string, now time.Time) DisplacedBooking {
	if prevReg == "" {
		return DisplacedBooking{}
	}
	if a := mailAddr(actor); a != "" {
		actor = a // an annotated creator ("pa@x (undo)") still matches themself
	}
	isMember := func(email string) bool {
		for _, m := range members {
			if strings.EqualFold(m, email) {
				return true
			}
		}
		return false
	}
	// The displaced booking is the newest-created live override whose car is
	// prevReg — the one that was winning the resolution until just now.
	var best *Override
	for i := range overrides {
		o := &overrides[i]
		if o.StartsAt.After(now) || (o.EndsAt != nil && !now.Before(*o.EndsAt)) {
			continue // not currently active
		}
		reg := o.Registration
		if reg == "" {
			reg = vehicles[o.VehicleID].Registration
		}
		if !strings.EqualFold(reg, prevReg) {
			continue
		}
		if best == nil || o.CreatedAt.After(best.CreatedAt) ||
			(o.CreatedAt.Equal(best.CreatedAt) && o.ID > best.ID) {
			best = o
		}
	}
	if best == nil {
		return DisplacedBooking{} // prevReg wasn't a live booking (roster or external)
	}
	contact := mailAddr(best.CreatedBy)
	if contact == "" || isMember(contact) {
		// Not booked by a reachable guest: fall back to the saved vehicle's
		// driver. (A member's own booking of a car with no attached email needs
		// no extra warning — the member hears via the account fanout.)
		memberBooking := contact != ""
		contact = ""
		if best.VehicleID != 0 {
			contact = vehicles[best.VehicleID].Email
		}
		if contact == "" && memberBooking {
			return DisplacedBooking{}
		}
	}
	if contact != "" && (strings.EqualFold(contact, actor) || isMember(contact)) {
		return DisplacedBooking{} // self-displacement, or the fanout covers it
	}
	return DisplacedBooking{Reg: prevReg, Contact: contact}
}
