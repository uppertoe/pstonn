package connectors

import (
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/provider/fake"
	"github.com/uppertoe/pstonn/internal/provider/orikan"
	"github.com/uppertoe/pstonn/internal/provider/orikanv7"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/tenant"
)

// TestEmbeddedRegistryBuildsEveryTenant is the "adding a tenant" guarantee: every
// entry in tenants.json — enabled or not — must build into a provider that calls
// itself by the descriptor's connector name and declares coherent capabilities.
// main builds them all at startup too, so a descriptor that fails here would fail
// the deploy; this test fails the commit instead.
func TestEmbeddedRegistryBuildsEveryTenant(t *testing.T) {
	reg, err := tenant.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range reg.All() {
		p, err := Build(c, nil)
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		if p.ID() != c.Connector {
			t.Errorf("%s: provider ID %q != connector %q", c.ID, p.ID(), c.Connector)
		}
		if err := p.Capabilities().Validate(); err != nil {
			t.Errorf("%s: %v", c.ID, err)
		}
		// An enabled tenant is one the scheduler will drive: it must be a plate
		// model (the registry enforces this too — belt and braces at the seam).
		if c.Enabled && !c.Model.Plate() {
			t.Errorf("%s: enabled with non-plate model %q", c.ID, c.Model)
		}
	}
	// Rows from before the tenant dimension are stamped with the legacy id; the
	// registry must keep describing it or those rows orphan on the next start.
	if _, ok := reg.ByID(store.LegacyTenantID); !ok {
		t.Errorf("embedded registry no longer describes the legacy tenant %q", store.LegacyTenantID)
	}
}

// TestConnectorNamesAgree holds the registry's list of connector names and this
// package's Build switch together: every name the registry accepts must build,
// and every connector package's ID must be a name the registry accepts. A new
// connector that is added on one side only fails here.
func TestConnectorNamesAgree(t *testing.T) {
	endpoints := tenant.Endpoints{
		Issuer: "https://a/idm", APIBase: "https://a/ssp",
		ClientID: "x", RedirectURI: "https://a/ssp/", Scopes: []string{"openid"},
	}
	accepted := map[string]bool{}
	for _, name := range tenant.Connectors() {
		accepted[name] = true
		p, err := Build(&tenant.Tenant{ID: "t", Connector: name, Model: tenant.ModelSwap, Endpoints: endpoints}, nil)
		if err != nil {
			t.Errorf("registry accepts %q but Build refuses it: %v", name, err)
			continue
		}
		if p.ID() != name {
			t.Errorf("%q built a provider calling itself %q", name, p.ID())
		}
	}
	for _, id := range []string{orikan.ID, orikanv7.ID, fake.ID} {
		if !accepted[id] {
			t.Errorf("connector %q has a package but the registry (tenant.Connectors) does not list it", id)
		}
	}
}

// TestBuildRefusesWhatItCannotDrive: the seam is where an undrivable pairing is
// caught, so no client (and no SetVehicle) can ever exist for it.
func TestBuildRefusesWhatItCannotDrive(t *testing.T) {
	endpoints := tenant.Endpoints{
		Issuer: "https://a/idm", APIBase: "https://a/ssp-svc",
		ClientID: "x", RedirectURI: "https://a/ssp/callback", Scopes: []string{"openid"},
	}
	cases := map[string]struct {
		t    tenant.Tenant
		want string
	}{
		"coupon model":          {tenant.Tenant{ID: "c", Connector: fake.ID, Model: tenant.ModelCoupon}, "no connector drives"},
		"paper model":           {tenant.Tenant{ID: "p", Connector: fake.ID, Model: tenant.ModelPaper}, "no connector drives"},
		"unknown connector":     {tenant.Tenant{ID: "u", Connector: "nope", Model: tenant.ModelSwap}, "no backend registered"},
		"orikan, no endpoints":  {tenant.Tenant{ID: "o", Connector: orikan.ID, Model: tenant.ModelSwap}, "needs endpoints"},
		"v7, partial endpoints": {tenant.Tenant{ID: "v", Connector: orikanv7.ID, Model: tenant.ModelSwap, Endpoints: tenant.Endpoints{Issuer: "https://a/idm"}}, "needs endpoints"},
	}
	for name, c := range cases {
		_, err := Build(&c.t, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, c.want)
		}
	}
	// The same descriptors with a plate model and endpoints DO build.
	if _, err := Build(&tenant.Tenant{ID: "o", Connector: orikan.ID, Model: tenant.ModelReplate, Endpoints: endpoints}, nil); err != nil {
		t.Errorf("replate (a plate model) should build: %v", err)
	}
}
