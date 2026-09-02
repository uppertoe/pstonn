package tenant

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
)

// tenantsJSON is the built-in registry: every tenant p.stonn knows how to talk
// to, whether or not it is enabled. Operators may replace it at runtime with
// COUNCILS_PATH (a file of the same shape), the TERMS_PATH pattern.
//
//go:embed tenants.json
var tenantsJSON []byte

// Registry is the set of registry this process serves.
type Registry struct {
	list []*Tenant
	byID map[string]*Tenant
	// Default is the tenant an account belongs to when it has made no choice:
	// the only enabled tenant, or the first enabled one.
	Default *Tenant
}

type registryFile struct {
	Tenants []*Tenant `json:"tenants"`
}

// LoadEmbedded parses the built-in registry with no overrides (a fresh copy:
// Load lays configuration over the entries it returns).
func LoadEmbedded() (*Registry, error) {
	return parse(tenantsJSON)
}

// embedded is the built-in registry parsed once, for the read-only lookups
// (Default, Stonnington) that every page render and email may make.
var embedded = sync.OnceValues(func() (*Registry, error) { return parse(tenantsJSON) })

// connectorSpec is what the registry knows about a connector name: whether it
// talks to a portal (and so must be given endpoints — which fields, the connector
// itself decides in connectors.Build). The set here and the cases in
// connectors.Build must agree; the connectors package's tests hold them together.
type connectorSpec struct{ portal bool }

var knownConnectors = map[string]connectorSpec{
	"orikan-ssp":    {portal: true},
	"orikan-ssp-v7": {portal: true},
	"fake":          {},
}

// Connectors lists the connector names the registry accepts, sorted.
func Connectors() []string {
	out := make([]string, 0, len(knownConnectors))
	for k := range knownConnectors {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Load builds the registry the process runs with: the file at path if given,
// else the embedded one; then the COUNCIL_* configuration laid over the
// stonnington entry (so a single-tenant deployment's overrides keep working),
// and sandbox mode narrowing the registry to one fake tenant.
func Load(cfg config.CouncilConfig, path string) (*Registry, error) {
	raw := tenantsJSON
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("tenants: read %s: %w", path, err)
		}
		raw = b
	}
	reg, err := parse(raw)
	if err != nil {
		return nil, err
	}
	if c, ok := reg.byID["stonnington"]; ok {
		applyConfig(c, cfg)
		// The overlay lands AFTER parse validated the file, so it must be checked
		// on its own: an http:// COUNCIL_ISSUER in the environment would otherwise
		// send residents' plaintext portal passwords over a scheme the registry
		// rule exists to forbid.
		if err := validateEndpoints(c.Endpoints); err != nil {
			return nil, fmt.Errorf("tenants: %s (COUNCIL_* override): %w", c.ID, err)
		}
	}
	if cfg.Sandbox {
		// The sandbox fakes ONE tenant in memory; it is what dev/demo runs against.
		c, ok := reg.byID["stonnington"]
		if !ok {
			c = reg.list[0]
		}
		c.Connector = "fake"
		c.Enabled = true
		reg = &Registry{list: []*Tenant{c}, byID: map[string]*Tenant{c.ID: c}}
	}
	reg.Default = nil
	for _, c := range reg.list {
		if c.Enabled {
			reg.Default = c
			break
		}
	}
	if reg.Default == nil {
		return nil, fmt.Errorf("tenants: no council is enabled")
	}
	return reg, nil
}

func parse(raw []byte) (*Registry, error) {
	var f registryFile
	// Unknown keys are refused: a misspelt field ("enable", "capactiy") would
	// otherwise be silently ignored and the tenant would run with the default.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("tenants: %w", err)
	}
	if len(f.Tenants) == 0 {
		return nil, fmt.Errorf("tenants: the registry is empty")
	}
	reg := &Registry{byID: map[string]*Tenant{}}
	for _, c := range f.Tenants {
		if err := validate(c); err != nil {
			return nil, fmt.Errorf("tenants: %s: %w", c.ID, err)
		}
		if _, dup := reg.byID[c.ID]; dup {
			return nil, fmt.Errorf("tenants: duplicate id %q", c.ID)
		}
		c.Policy = c.Policy.compiled()
		reg.byID[c.ID] = c
		reg.list = append(reg.list, c)
	}
	return reg, nil
}

// validate rejects a descriptor the app could not run safely: an id that would
// not survive a URL or a database key, an unknown connector, a real connector
// with no endpoints, a timezone Go cannot load, or a policy that matches nothing.
func validate(c *Tenant) error {
	if c.ID == "" || strings.ToLower(c.ID) != c.ID || strings.ContainsAny(c.ID, " /\\?#") {
		return fmt.Errorf("invalid id %q (lower-case, no spaces or URL characters)", c.ID)
	}
	if c.Name == "" || c.Short == "" {
		return fmt.Errorf("name and short are required")
	}
	spec, ok := knownConnectors[c.Connector]
	if !ok {
		return fmt.Errorf("unknown connector %q (one of %s)", c.Connector, strings.Join(Connectors(), ", "))
	}
	e := c.Endpoints
	if spec.portal && e.Issuer == "" && e.APIBase == "" && e.ClientID == "" && e.RedirectURI == "" {
		return fmt.Errorf("%s talks to a portal and needs endpoints", c.Connector)
	}
	if err := validateEndpoints(e); err != nil {
		return err
	}
	if c.Timezone == "" {
		return fmt.Errorf("timezone is required")
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return fmt.Errorf("timezone %q: %w", c.Timezone, err)
	}
	if !c.Model.Known() {
		return fmt.Errorf("unknown model %q (swap, replate, coupon or paper)", c.Model)
	}
	// A plate model schedules by writing a plate onto a permit, so it needs at
	// least one schedulable permit type: a visitor-named permit, or a resident
	// permit the policy opts into scheduling (the re-plate model). Coupon and paper
	// don't schedule a plate, so they carry no such requirement.
	if c.Model.Plate() && c.Policy.VisitorWord == "" && !(c.Policy.ScheduleResident && c.Policy.ResidentWord != "") {
		return fmt.Errorf("a %s tenant needs policy.visitor_word, or schedule_resident with resident_word (nothing would be schedulable)", c.Model)
	}
	// Only plate models have a scheduler today. A coupon council needs a date-based
	// planner and a paper one has nothing to automate, so either may be described in
	// the registry but must stay disabled until (if) its product ships — enabling it
	// would offer residents a scheme p.stonn cannot actually drive.
	if c.Enabled && !c.Model.Plate() {
		return fmt.Errorf("model %q has no scheduler yet; keep the tenant disabled until it does", c.Model)
	}
	// Re-plate shares swap's write contract but not its clear semantics: with no
	// roster entry the resident's OWN car must go back on the permit, and that
	// restore path does not exist yet — the reconcile loop would ClearVehicle a
	// resident permit and leave their everyday car uncovered. Describable, not
	// enableable, until it does.
	if c.Enabled && c.Model == ModelReplate {
		return fmt.Errorf("model %q cannot be enabled yet: the scheduler has no home-vehicle restore path (it would clear the resident's own permit)", c.Model)
	}
	// Links land in href attributes across the site; only http(s) may.
	for name, raw := range map[string]string{"portal": c.Links.Portal, "register": c.Links.Register, "reset_password": c.Links.ResetPassword,
		"apply_visitor": c.Links.ApplyVisitor, "permits": c.Links.Permits, "faq": c.Links.FAQ} {
		if raw == "" {
			continue
		}
		if u, err := url.Parse(raw); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("links.%s must be an http(s) URL, got %q", name, raw)
		}
	}
	return nil
}

// validateEndpoints applies the one rule that must hold wherever endpoints come
// from — the registry file or a COUNCIL_* override. The login flow carries a
// resident's plaintext tenant password; the scheme it may travel over is decided
// here and nowhere else. Any endpoint given — for any connector — must be https.
func validateEndpoints(e Endpoints) error {
	for name, raw := range map[string]string{"issuer": e.Issuer, "api_base": e.APIBase, "redirect_uri": e.RedirectURI} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("%s must be an https URL, got %q", name, raw)
		}
	}
	return nil
}

// ByID looks a tenant up.
func (r *Registry) ByID(id string) (*Tenant, bool) {
	c, ok := r.byID[id]
	return c, ok
}

// All returns every tenant in registry order.
func (r *Registry) All() []*Tenant { return append([]*Tenant(nil), r.list...) }

// Enabled returns the registry residents may sign up with.
func (r *Registry) Enabled() []*Tenant {
	var out []*Tenant
	for _, c := range r.list {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out
}

// Location returns the tenant's timezone (validated at load).
func (c *Tenant) Location() *time.Location {
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return time.UTC
	}
	return loc
}
