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
		return Resolution{VehicleID: best.VehicleID, Registration: best.Registration, Source: SourceOverride}
	}

	wd := now.Weekday()
	for _, r := range rules {
		if r.Weekday == wd {
			return Resolution{VehicleID: r.VehicleID, Source: SourceRoster}
		}
	}
	return Resolution{Source: SourceNone}
}
