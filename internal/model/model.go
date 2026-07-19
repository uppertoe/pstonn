// Package model holds the core domain types, kept free of any persistence or
// HTTP concerns so the scheduling logic can be unit-tested in isolation.
package model

import "time"

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
	ActiveRegistration string // last registration we know is allocated
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
		if best == nil || o.CreatedAt.After(best.CreatedAt) {
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
