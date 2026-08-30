package tenant

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
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

// LoadEmbedded parses the built-in registry with no overrides.
func LoadEmbedded() (*Registry, error) {
	return parse(tenantsJSON)
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
	if err := json.Unmarshal(raw, &f); err != nil {
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
	switch c.Connector {
	case "orikan-ssp", "orikan-ssp-v7":
		// Both Orikan generations need the same endpoint fields; they differ in what
		// api_base points at (orikan-ssp: the /ssp-svc JSON API; orikan-ssp-v7: the
		// /ssp server-rendered app) and in the auth flow, which the connector owns.
		e := c.Endpoints
		if e.Issuer == "" || e.APIBase == "" || e.ClientID == "" || e.RedirectURI == "" || len(e.Scopes) == 0 {
			return fmt.Errorf("%s needs issuer, api_base, client_id, redirect_uri and scopes", c.Connector)
		}
		// The login flow carries a resident's plaintext tenant password; the
		// scheme it may travel over is decided here and nowhere else.
		for name, raw := range map[string]string{"issuer": e.Issuer, "api_base": e.APIBase, "redirect_uri": e.RedirectURI} {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return fmt.Errorf("%s must be an https URL, got %q", name, raw)
			}
		}
	case "fake":
	default:
		return fmt.Errorf("unknown connector %q", c.Connector)
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
