package council

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

// councilsJSON is the built-in registry: every council p.stonn knows how to talk
// to, whether or not it is enabled. Operators may replace it at runtime with
// COUNCILS_PATH (a file of the same shape), the TERMS_PATH pattern.
//
//go:embed councils.json
var councilsJSON []byte

// Registry is the set of councils this process serves.
type Registry struct {
	list []*Council
	byID map[string]*Council
	// Default is the council an account belongs to when it has made no choice:
	// the only enabled council, or the first enabled one.
	Default *Council
}

type registryFile struct {
	Councils []*Council `json:"councils"`
}

// LoadEmbedded parses the built-in registry with no overrides.
func LoadEmbedded() (*Registry, error) {
	return parse(councilsJSON)
}

// Load builds the registry the process runs with: the file at path if given,
// else the embedded one; then the COUNCIL_* configuration laid over the
// stonnington entry (so a single-council deployment's overrides keep working),
// and sandbox mode narrowing the registry to one fake council.
func Load(cfg config.CouncilConfig, path string) (*Registry, error) {
	raw := councilsJSON
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("councils: read %s: %w", path, err)
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
		// The sandbox fakes ONE council in memory; it is what dev/demo runs against.
		c, ok := reg.byID["stonnington"]
		if !ok {
			c = reg.list[0]
		}
		c.Connector = "fake"
		c.Enabled = true
		reg = &Registry{list: []*Council{c}, byID: map[string]*Council{c.ID: c}}
	}
	reg.Default = nil
	for _, c := range reg.list {
		if c.Enabled {
			reg.Default = c
			break
		}
	}
	if reg.Default == nil {
		return nil, fmt.Errorf("councils: no council is enabled")
	}
	return reg, nil
}

func parse(raw []byte) (*Registry, error) {
	var f registryFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("councils: %w", err)
	}
	if len(f.Councils) == 0 {
		return nil, fmt.Errorf("councils: the registry is empty")
	}
	reg := &Registry{byID: map[string]*Council{}}
	for _, c := range f.Councils {
		if err := validate(c); err != nil {
			return nil, fmt.Errorf("councils: %s: %w", c.ID, err)
		}
		if _, dup := reg.byID[c.ID]; dup {
			return nil, fmt.Errorf("councils: duplicate id %q", c.ID)
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
func validate(c *Council) error {
	if c.ID == "" || strings.ToLower(c.ID) != c.ID || strings.ContainsAny(c.ID, " /\\?#") {
		return fmt.Errorf("invalid id %q (lower-case, no spaces or URL characters)", c.ID)
	}
	if c.Name == "" || c.Short == "" {
		return fmt.Errorf("name and short are required")
	}
	switch c.Connector {
	case "orikan-ssp":
		e := c.Endpoints
		if e.Issuer == "" || e.APIBase == "" || e.ClientID == "" || e.RedirectURI == "" || len(e.Scopes) == 0 {
			return fmt.Errorf("orikan-ssp needs issuer, api_base, client_id, redirect_uri and scopes")
		}
		// The login flow carries a resident's plaintext council password; the
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
	if c.Policy.VisitorWord == "" {
		return fmt.Errorf("policy.visitor_word is required (nothing would be schedulable)")
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

// ByID looks a council up.
func (r *Registry) ByID(id string) (*Council, bool) {
	c, ok := r.byID[id]
	return c, ok
}

// All returns every council in registry order.
func (r *Registry) All() []*Council { return append([]*Council(nil), r.list...) }

// Enabled returns the councils residents may sign up with.
func (r *Registry) Enabled() []*Council {
	var out []*Council
	for _, c := range r.list {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out
}

// Location returns the council's timezone (validated at load).
func (c *Council) Location() *time.Location {
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return time.UTC
	}
	return loc
}
