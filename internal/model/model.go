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

// ExpiryDeadline is the instant a permit with this end date stops being valid:
// midnight at the START of the day after EndDate, in loc. EndDate is the
// INCLUSIVE last valid day and the council reports it as a zoneless local date
// (which we parse as UTC midnight), so anything that compares `now` against the
// bare instant treats the permit as finished from ~10-11am local on its final
// valid day — while it is still usable and still needs its plate kept right.
// Every "has this permit finished?" question must go through here so that
// off-by-one is fixed in one place. Zero end date has no deadline, so callers
// must check for it themselves.
func ExpiryDeadline(endDate time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.Local
	}
	end := endDate.In(loc)
	return time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, 1)
}

// Inactive reports whether a permit should no longer be actively reconciled or
// shown as a live permit: its status says it's dead, or its expiry day has fully
// passed. Retiring only once the day AFTER EndDate has begun locally (see
// ExpiryDeadline) is deliberately conservative — erring early could stop us
// updating a live permit and cause a fine, while erring late only costs a
// harmless doomed write. Zero end date + live status = active (we never retire on
// unknown data).
func (p Permit) Inactive(now time.Time, loc *time.Location) bool {
	if deadStatus(p.Status) {
		return true
	}
	if p.EndDate.IsZero() {
		return false
	}
	return !now.Before(ExpiryDeadline(p.EndDate, loc))
}

// NormPlate canonicalises a registration for comparison. The council echoes
// plates back in whatever case and spacing they were entered with, and no two
// real cars differ only by case or by a space, so neither may make two spellings
// of one plate look like two different cars.
func NormPlate(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		b.WriteRune(r)
	}
	return strings.ToUpper(b.String())
}

// SamePlate reports whether two registrations name the same car.
//
// This is the ONLY rule for comparing a permit's active registration against
// anything, because the sites that decide "is a council write needed?" and "has
// the plate changed?" must not disagree: when one of them says a case-variant
// echo from the portal is a different plate, p.stonn performs a real council
// write, tells the household their permit was updated, and emails a displaced
// driver — all for a no-op.
func SamePlate(a, b string) bool {
	return NormPlate(a) == NormPlate(b)
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

	// Since is when this allocation BECAME the right answer: local midnight for a
	// roster day, the start (or booking time) of a winning override. Zero for
	// SourceNone.
	Since time.Time

	// Scheduled distinguishes a change the CLOCK brought about from one a person
	// just asked for. A roster day rolling over at midnight is scheduled; so is a
	// booking made last week whose start time has now arrived. A booking or guest
	// activation that takes effect the moment it is made is NOT — somebody is
	// standing there waiting for it.
	//
	// It exists so the rollover spread can delay the first kind (nobody is
	// watching, and 500 households sharing a midnight boundary is the worst burst
	// the council sees) without ever delaying the second.
	Scheduled bool
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
		// An override takes effect when its window opens, or when it was booked if
		// that is later (a booking backdated over a window already in progress takes
		// effect the moment it is made). Comparing the two is also what says whether
		// a person is waiting on this: StartsAt after CreatedAt means it was booked
		// in advance and the clock brought it about.
		since, scheduled := best.CreatedAt, false
		if best.StartsAt.After(best.CreatedAt) {
			since, scheduled = best.StartsAt, true
		}
		return Resolution{
			VehicleID: best.VehicleID, Registration: best.Registration,
			Source: SourceOverride, By: best.CreatedBy,
			Since: since, Scheduled: scheduled,
		}
	}

	wd := now.Weekday()
	for _, r := range rules {
		if r.Weekday == wd {
			// A roster day begins at local midnight, and now is already in the
			// timezone rosters are expressed in (see the doc comment), so the day
			// boundary is read straight off it.
			midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
			return Resolution{VehicleID: r.VehicleID, Source: SourceRoster, Since: midnight, Scheduled: true}
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
