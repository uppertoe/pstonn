// Package council describes a council tenant: which portal it runs, how p.stonn
// talks to it, which of its permit types may be scheduled, and the names and links
// its residents see. It is the seam between the council-agnostic app (schedules,
// vehicles, guests, notifications) and the one council the app is currently wired
// to, so that a second council is a descriptor plus a capture rather than a rewrite.
// See docs/council-connections.md.
//
// The protocol driver itself (login, session renewal, permit reads and writes)
// lives in internal/parking; a descriptor names the connector it needs and the
// parameters to build it with. Phase 0 (now) has exactly one descriptor —
// Stonnington — built from the existing COUNCIL_* configuration.
package council

import (
	"regexp"
	"strings"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/parking"
)

// Council is a tenant descriptor. Fields are plain data so a descriptor can later
// be loaded from a file; behaviour hangs off PermitPolicy.
type Council struct {
	// ID is the stable identifier: it will key database rows and appear in URLs,
	// so it never changes once a council is live. Lower-case, no spaces.
	ID string
	// Name is the council's full name as residents know it ("City of Stonnington");
	// Short is the bare place name used mid-sentence ("Stonnington").
	Name  string
	Short string
	// Connector names the protocol driver: "orikan-ssp" (the Orikan ePermits
	// self-service portal: Duende IdentityServer + /ssp-svc) or "fake" (the
	// in-memory sandbox).
	Connector string
	// Endpoints parameterise the connector.
	Endpoints Endpoints
	// Timezone is the IANA zone the council's permit days are reckoned in.
	Timezone string
	// Policy decides which of the council's permit types p.stonn may schedule.
	Policy PermitPolicy
	// Links are the council's own pages residents are sent to.
	Links Links
	// Copy is council-specific prose and facts for the public pages.
	Copy Copy
	// Enabled gates sign-up; Capacity (0 = unlimited) caps linked accounts.
	Enabled  bool
	Capacity int
}

// Endpoints are the connector's parameters for an Orikan ePermits tenant.
type Endpoints struct {
	Issuer      string   // OIDC issuer, …/idm
	APIBase     string   // …/ssp-svc
	ClientID    string   // the public SPA client the portal itself uses
	RedirectURI string   // that client's registered callback; the code is read off the 302
	Scopes      []string // no offline_access — the client rejects it
}

// Links are the council's own pages residents are sent to.
type Links struct {
	Portal        string // the self-service permit portal's front door
	Register      string // create a portal account
	ResetPassword string // forgotten-password page
	ApplyVisitor  string // the council's page on applying for a visitor permit
}

// Copy is council-specific prose and facts. It is deliberately small: anything
// that reads as a sentence belongs in the message catalog (see the i18n section of
// docs/council-connections.md), keyed by council where it differs.
type Copy struct {
	Suburbs []string // the suburbs the council's permit scheme covers, for the landing page
	Phone   string   // the council's public switchboard, as printed on its site
}

// PermitPolicy decides which of a council's permit types p.stonn may schedule. The
// council owns the display names, so the policy is name-based with a guarded
// fallback on the council's own "holder may change the vehicle" flag.
type PermitPolicy struct {
	// VisitorWord is the case-insensitive substring that identifies the shared
	// visitor permit type, the only kind p.stonn schedules ("visitor" matches
	// "(A) 1st Visitor Permit").
	VisitorWord string
	// ResidentWord is matched as a whole word, case-insensitively, to identify a
	// resident permit — one that holds the resident's OWN car and must never be
	// scheduled even when it is changeable. Whole-word so that "Residential
	// Tradesperson Permit" (a different type) is not caught by accident.
	ResidentWord string
	// DefaultVehicleState is the portal's vehicle-state id for the council's own
	// state, used when a plate is written without a prior state to copy
	// (VIC=1 ACT=2 NSW=3 WA=4 TAS=5 QLD=6 SA=7 NT=8).
	DefaultVehicleState string

	residentRe *regexp.Regexp
}

// IsVisitor reports whether a permit type is the schedulable visitor type.
func (p PermitPolicy) IsVisitor(permitType string) bool {
	return p.VisitorWord != "" && strings.Contains(strings.ToLower(permitType), strings.ToLower(p.VisitorWord))
}

// IsResident reports whether a permit type is a resident permit (the holder's own
// car), which is never scheduled.
func (p PermitPolicy) IsResident(permitType string) bool {
	re := p.residentRe
	if re == nil {
		if p.ResidentWord == "" {
			return false
		}
		re = regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(p.ResidentWord) + `\b`)
	}
	return re.MatchString(permitType)
}

// NameFallback reports whether the name match should be bypassed for this
// account: the council owns the display text, and a rename ("visitor" → anything
// else) would otherwise make every permit unaddable overnight. When NO permit
// matches the name but the council says at least one permit's vehicle can be
// changed — its own authorization signal for exactly the operation p.stonn
// performs — those permits may be offered with a caution instead of a dead end.
// Scoped to the no-match case on purpose: while the name works it stays the
// primary filter, because other types (resident permits included) are changeable.
func (p PermitPolicy) NameFallback(permits []parking.PermitInfo) bool {
	anyChangeable := false
	for _, pi := range permits {
		if p.IsVisitor(pi.PermitType) {
			return false
		}
		if pi.CanChangeVehicle {
			anyChangeable = true
		}
	}
	return anyChangeable
}

// Schedulable reports whether a permit's TYPE may be scheduled: a visitor-named
// permit, or — only under NameFallback — a changeable permit that is not a resident
// permit. The picker's hint and addPermit's gate both call this so they cannot
// drift. Resident permits are excluded even under fallback: they hold the holder's
// own everyday vehicle and are themselves changeable, so offering one would let
// p.stonn overwrite the resident's own plate.
func (p PermitPolicy) Schedulable(pi parking.PermitInfo, fallback bool) bool {
	return p.IsVisitor(pi.PermitType) || (fallback && pi.CanChangeVehicle && !p.IsResident(pi.PermitType))
}

// compiled returns the policy with its regexp built once.
func (p PermitPolicy) compiled() PermitPolicy {
	if p.ResidentWord != "" {
		p.residentRe = regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(p.ResidentWord) + `\b`)
	}
	return p
}

// Stonnington is the City of Stonnington descriptor with its confirmed policy and
// links. Endpoints are filled in by FromConfig (they default to Stonnington's in
// config, and COUNCIL_* overrides still apply).
func Stonnington() *Council {
	return &Council{
		ID:        "stonnington",
		Name:      "City of Stonnington",
		Short:     "Stonnington",
		Connector: "orikan-ssp",
		Timezone:  "Australia/Melbourne",
		Policy: PermitPolicy{
			VisitorWord:         "visitor",
			ResidentWord:        "resident",
			DefaultVehicleState: "1", // VIC
		}.compiled(),
		Links: Links{
			Portal:        "https://parkingpermits.stonnington.vic.gov.au/",
			Register:      "https://parkingpermits.stonnington.vic.gov.au/idm/account/Register",
			ResetPassword: "https://parkingpermits.stonnington.vic.gov.au/idm/account/ForgotPassword",
			ApplyVisitor:  "https://www.stonnington.vic.gov.au/Services/Parking/Parking-permits/Visitor-parking-permits",
		},
		Copy: Copy{
			Suburbs: []string{"Prahran", "Windsor", "South Yarra", "Toorak", "Armadale", "Malvern", "Malvern East", "Kooyong"},
			Phone:   "03 8290 1333",
		},
		Enabled: true,
	}
}

// FromConfig returns the council the process is wired to. Phase 0: always
// Stonnington, with the connector endpoints taken from COUNCIL_* config so an
// operator override keeps working; in sandbox mode the connector is "fake".
func FromConfig(cfg config.CouncilConfig) *Council {
	c := Stonnington()
	c.Endpoints = Endpoints{
		Issuer:      cfg.Issuer,
		APIBase:     cfg.APIBase,
		ClientID:    cfg.ClientID,
		RedirectURI: cfg.RedirectURI,
		Scopes:      append([]string(nil), cfg.Scopes...),
	}
	if cfg.Sandbox {
		c.Connector = "fake"
	}
	return c
}
