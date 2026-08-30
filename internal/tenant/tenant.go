// Package tenant describes a tenant tenant: which portal it runs, how p.stonn
// talks to it, which of its permit types may be scheduled, and the names and links
// its residents see. It is the seam between the tenant-agnostic app (schedules,
// vehicles, guests, notifications) and the one tenant the app is currently wired
// to, so that a second tenant is a descriptor plus a capture rather than a rewrite.
// See docs/tenant-connections.md.
//
// The protocol driver itself (login, session renewal, permit reads and writes)
// lives in internal/parking; a descriptor names the connector it needs and the
// parameters to build it with. Phase 0 (now) has exactly one descriptor —
// Stonnington — built from the existing COUNCIL_* configuration.
package tenant

import (
	"regexp"
	"strings"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/parking"
)

// Model is the shape of a tenant's visitor-permit scheme — the axis that decides
// which scheduler and which UI apply, orthogonal to Connector (the wire protocol).
// One connector can back several models (Orikan SSP backs both a swap and a coupon
// council) and one model spans several connectors, so the two are separate fields
// read by different parts of the app: Connector selects the provider.Provider,
// Model selects how p.stonn schedules against it. See docs/council-survey.md.
//
// The set is open by design: a new scheme is a new constant added to knownModels
// (and, when it needs a different write path, a Plate() answer and its own
// planner) — never a schema migration.
type Model string

const (
	// ModelSwap: a standing visitor permit with no fixed plate; the holder edits
	// the plate online. What p.stonn does today (Stonnington, Banyule).
	ModelSwap Model = "swap"
	// ModelReplate: no visitor product; the resident temporarily edits the plate on
	// their own resident permit, displacing their everyday car (Brimbank, Kingston).
	// Same plate-write contract and scheduler as swap; differs only in policy
	// (resident permit is schedulable; "no roster entry" restores a home vehicle
	// rather than clearing).
	ModelReplate Model = "replate"
	// ModelCoupon: a yearly book of single-day allocations (plate + date), spent
	// rather than kept-correct (Glen Eira, Merri-bek). A different provider surface
	// and a date-based planner; recognised here but not yet driven (see Plate).
	ModelCoupon Model = "coupon"
	// ModelPaper: a physical tag handed over. Nothing to automate; present so a
	// paper council can still be described in the registry.
	ModelPaper Model = "paper"
)

// knownModels is the closed-for-validation, open-for-extension set: a descriptor's
// model must be one of these, and adding a scheme means adding it here.
var knownModels = map[Model]bool{ModelSwap: true, ModelReplate: true, ModelCoupon: true, ModelPaper: true}

// Known reports whether the model is one the registry recognises.
func (m Model) Known() bool { return knownModels[m] }

// Plate reports whether the model schedules by writing a plate onto a permit — the
// SetVehicle/ClearVehicle contract the reconcile scheduler drives. True for swap
// and replate; false for coupon (a date-based planner, not yet built) and paper.
// The plate-swap path guards on this so a coupon tenant can never reach SetVehicle.
func (m Model) Plate() bool { return m == ModelSwap || m == ModelReplate }

// Tenant is a tenant descriptor. Fields are plain data so a descriptor can later
// be loaded from a file; behaviour hangs off Model and PermitPolicy.
type Tenant struct {
	// ID is the stable identifier: it keys database rows and appears in URLs, so
	// it never changes once a tenant is live. Lower-case, no spaces.
	ID string `json:"id"`
	// Name is the tenant's full name as residents know it ("City of Stonnington");
	// Short is the bare place name used mid-sentence ("Stonnington").
	Name  string `json:"name"`
	Short string `json:"short"`
	// Connector names the protocol driver: "orikan-ssp" (the Orikan ePermits
	// self-service portal: Duende IdentityServer + /ssp-svc) or "fake" (the
	// in-memory sandbox).
	Connector string `json:"connector"`
	// Model is the shape of the scheme (swap / replate / coupon / paper) — the axis
	// that decides the scheduler and UI, independent of Connector. Required.
	Model Model `json:"model"`
	// Endpoints parameterise the connector.
	Endpoints Endpoints `json:"endpoints"`
	// Timezone is the IANA zone the tenant's permit days are reckoned in.
	Timezone string `json:"timezone"`
	// Policy decides which of the tenant's permit types p.stonn may schedule.
	Policy PermitPolicy `json:"policy"`
	// Links are the tenant's own pages residents are sent to.
	Links Links `json:"links"`
	// Copy is tenant-specific prose and facts for the public pages.
	Copy Copy `json:"copy"`
	// Terms is the tenant's own vocabulary, laid over the catalog defaults (see
	// internal/i18n): what it calls its portal, its permits, its parking brand.
	Terms map[string]string `json:"terms"`
	// Enabled gates sign-up; Capacity (0 = unlimited) caps linked accounts.
	Enabled  bool `json:"enabled"`
	Capacity int  `json:"capacity"`
}

// Endpoints are the connector's parameters for an Orikan ePermits tenant.
type Endpoints struct {
	Issuer      string   `json:"issuer"`       // OIDC issuer, …/idm
	APIBase     string   `json:"api_base"`     // …/ssp-svc
	ClientID    string   `json:"client_id"`    // the public SPA client the portal itself uses
	RedirectURI string   `json:"redirect_uri"` // that client's registered callback; the code is read off the 302
	Scopes      []string `json:"scopes"`       // no offline_access — the client rejects it
}

// Links are the tenant's own pages residents are sent to.
type Links struct {
	Portal        string `json:"portal"`         // the self-service permit portal's front door
	Register      string `json:"register"`       // create a portal account
	ResetPassword string `json:"reset_password"` // forgotten-password page
	ApplyVisitor  string `json:"apply_visitor"`  // the tenant's page on applying for a visitor permit
	Permits       string `json:"permits"`        // the tenant's parking-permits overview page
	FAQ           string `json:"faq"`            // the tenant's permit FAQ page
}

// Copy is tenant-specific prose and facts. It is deliberately small: anything
// that reads as a sentence belongs in the message catalog (see the i18n section of
// docs/tenant-connections.md), keyed by tenant where it differs.
type Copy struct {
	Suburbs []string `json:"suburbs"` // the suburbs the tenant's permit scheme covers, for the landing page
	Phone   string   `json:"phone"`   // the tenant's public switchboard, as printed on its site
}

// PermitPolicy decides which of a tenant's permit types p.stonn may schedule. The
// tenant owns the display names, so the policy is name-based with a guarded
// fallback on the tenant's own "holder may change the vehicle" flag.
type PermitPolicy struct {
	// VisitorWord is the case-insensitive substring that identifies the shared
	// visitor permit type, the only kind p.stonn schedules ("visitor" matches
	// "(A) 1st Visitor Permit").
	VisitorWord string `json:"visitor_word"`
	// ResidentWord is matched as a whole word, case-insensitively, to identify a
	// resident permit — one that holds the resident's OWN car and must never be
	// scheduled even when it is changeable. Whole-word so that "Residential
	// Tradesperson Permit" (a different type) is not caught by accident.
	ResidentWord string `json:"resident_word"`
	// HomeState is the tenant's own registration state, as a CODE (e.g. "VIC"),
	// written when a plate carries no state of its own. The connector maps the code
	// to the portal's id; empty or unrecognised falls back to VIC.
	HomeState string `json:"home_state"`
	// ScheduleResident says a resident permit (ResidentWord) MAY be scheduled. False
	// (the default, and Stonnington) keeps a resident permit off-limits even when the
	// platform reports it changeable — its T&Cs bind it to the holder's own car.
	// True is the re-plate model (Brimbank, Glen Eira's 3.3.1): the resident permit
	// IS the visitor mechanism, so it is schedulable directly, not only under
	// fallback. Turning this on is a policy decision per council, not a capability.
	ScheduleResident bool `json:"schedule_resident"`

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
// account: the tenant owns the display text, and a rename ("visitor" → anything
// else) would otherwise make every permit unaddable overnight. When NO permit
// matches the name but the tenant says at least one permit's vehicle can be
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

// Schedulable reports whether a permit's TYPE may be scheduled. A visitor-named
// permit always is. A resident permit is schedulable only when the tenant's policy
// opts in (ScheduleResident — the re-plate model, where the resident permit is the
// visitor mechanism); otherwise it stays off-limits even under fallback, because it
// holds the holder's own everyday vehicle and is itself changeable, so offering it
// would let p.stonn overwrite the resident's own plate. Any other changeable,
// non-resident type is offered only under NameFallback. The picker's hint and
// addPermit's gate both call this so they cannot drift.
func (p PermitPolicy) Schedulable(pi parking.PermitInfo, fallback bool) bool {
	if p.IsVisitor(pi.PermitType) {
		return true
	}
	if p.IsResident(pi.PermitType) {
		return p.ScheduleResident
	}
	return fallback && pi.CanChangeVehicle
}

// compiled returns the policy with its regexp built once.
func (p PermitPolicy) compiled() PermitPolicy {
	if p.ResidentWord != "" {
		p.residentRe = regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(p.ResidentWord) + `\b`)
	}
	return p
}

// Default is the embedded registry's default tenant (a copy): the fallback
// wherever a page or message is rendered with no resolvable tenant.
func Default() *Tenant {
	reg, err := LoadEmbedded()
	if err != nil {
		panic(err) // the embedded registry is validated by tests
	}
	var c *Tenant
	for _, e := range reg.list {
		if e.Enabled {
			c = e
			break
		}
	}
	if c == nil {
		c = reg.list[0]
	}
	cp := *c
	return &cp
}

// Stonnington is the City of Stonnington descriptor from the embedded registry
// (a copy; the registry's own entry is not shared).
func Stonnington() *Tenant {
	reg, err := LoadEmbedded()
	if err != nil {
		panic(err) // the embedded registry is validated by tests
	}
	c, _ := reg.ByID("stonnington")
	cp := *c
	return &cp
}

// FromConfig returns the tenant the single-tenant configuration describes:
// Stonnington, with the connector endpoints taken from COUNCIL_* config so an
// operator override keeps working; in sandbox mode the connector is "fake".
func FromConfig(cfg config.CouncilConfig) *Tenant {
	c := Stonnington()
	applyConfig(c, cfg)
	return c
}

// applyConfig lays the COUNCIL_* settings over a descriptor's endpoints.
func applyConfig(c *Tenant, cfg config.CouncilConfig) {
	if cfg.Issuer != "" {
		c.Endpoints.Issuer = cfg.Issuer
	}
	if cfg.APIBase != "" {
		c.Endpoints.APIBase = cfg.APIBase
	}
	if cfg.ClientID != "" {
		c.Endpoints.ClientID = cfg.ClientID
	}
	if cfg.RedirectURI != "" {
		c.Endpoints.RedirectURI = cfg.RedirectURI
	}
	if len(cfg.Scopes) > 0 {
		c.Endpoints.Scopes = append([]string(nil), cfg.Scopes...)
	}
	if cfg.Sandbox {
		c.Connector = "fake"
	}
}
