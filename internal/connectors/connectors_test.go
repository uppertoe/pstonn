package connectors

import (
	"errors"
	"testing"

	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/provider/fake"
	"github.com/uppertoe/pstonn/internal/provider/orikan"
	"github.com/uppertoe/pstonn/internal/provider/orikanv7"
	"github.com/uppertoe/pstonn/internal/tenant"
)

// TestBuildRoutesEveryConnector locks the single seam: each registered connector
// name maps to its backend, and an unknown one is a loud error rather than a nil
// provider. A new connector must add a row here.
func TestBuildRoutesEveryConnector(t *testing.T) {
	orikanEndpoints := tenant.Endpoints{
		Issuer: "https://a/idm", APIBase: "https://a/ssp-svc",
		ClientID: "x", RedirectURI: "https://a/ssp/callback", Scopes: []string{"openid"},
	}
	v7Endpoints := tenant.Endpoints{
		Issuer: "https://a/idm", APIBase: "https://a/ssp",
		ClientID: "ePermits.ssp.web.v7", RedirectURI: "https://a/ssp/", Scopes: []string{"openid", "profile"},
	}
	cases := []struct {
		connector string
		endpoints tenant.Endpoints
		wantID    string
	}{
		{orikan.ID, orikanEndpoints, orikan.ID},
		{orikanv7.ID, v7Endpoints, orikanv7.ID},
		{fake.ID, tenant.Endpoints{}, fake.ID},
	}
	for _, c := range cases {
		p, err := Build(&tenant.Tenant{ID: "t", Connector: c.connector, Endpoints: c.endpoints}, nil)
		if err != nil {
			t.Fatalf("%s: Build error: %v", c.connector, err)
		}
		if p == nil {
			t.Fatalf("%s: Build returned a nil provider", c.connector)
		}
		if p.ID() != c.wantID {
			t.Errorf("%s: provider ID = %q, want %q", c.connector, p.ID(), c.wantID)
		}
	}

	if _, err := Build(&tenant.Tenant{ID: "t", Connector: "nope"}, nil); err == nil {
		t.Error("an unknown connector must be an error, not a nil provider")
	}
}

// TestV7SkeletonIsHonest: the v7 connector satisfies the contract but reports every
// uncaptured op as ErrNotCaptured, so a wrongly-enabled descriptor fails loudly
// rather than silently no-op'ing a resident's permit.
func TestV7SkeletonIsHonest(t *testing.T) {
	c := orikanv7.New(orikanv7.Config{})
	if _, err := c.Login(t.Context(), provider.Credentials{}); !errors.Is(err, provider.ErrNotCaptured) {
		t.Errorf("Login err = %v, want ErrNotCaptured", err)
	}
	if err := c.SetVehicle(t.Context(), nil, provider.PermitRef{}, provider.Vehicle{}); !errors.Is(err, provider.ErrNotCaptured) {
		t.Errorf("SetVehicle err = %v, want ErrNotCaptured", err)
	}
}
