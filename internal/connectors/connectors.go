// Package connectors is the ONE place that knows the concrete permit backends.
//
// It maps a tenant descriptor's connector name to a provider.Provider, translating
// the registry entry into whatever config that connector needs. Nothing else in
// the app imports a connector: the generic client (internal/parking), the
// scheduler, the server and the tenant mux all speak only the provider.Provider
// contract. So adding a backend — a different Orikan generation, another vendor, a
// scraped server-rendered portal — is a single case here plus its own package; the
// user-facing product does not change.
package connectors

import (
	"fmt"
	"net/http"

	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/provider/fake"
	"github.com/uppertoe/pstonn/internal/provider/orikan"
	"github.com/uppertoe/pstonn/internal/provider/orikanv7"
	"github.com/uppertoe/pstonn/internal/tenant"
)

// Build returns the provider that backs a tenant, on the given transport (the
// governed/counted RoundTripper the generic client reports traffic for). The
// connector name comes from the registry entry (COUNCIL_SANDBOX rewrites it to
// the fake in the registry, so no sandbox branch is needed here).
func Build(t *tenant.Tenant, tr http.RoundTripper) (provider.Provider, error) {
	switch t.Connector {
	case orikan.ID:
		return orikan.New(orikan.Config{
			Issuer:      t.Endpoints.Issuer,
			APIBase:     t.Endpoints.APIBase,
			ClientID:    t.Endpoints.ClientID,
			RedirectURI: t.Endpoints.RedirectURI,
			Scopes:      t.Endpoints.Scopes,
			HomeState:   t.Policy.HomeState,
		}, tr), nil
	case orikanv7.ID:
		return orikanv7.New(orikanv7.Config{
			Issuer:      t.Endpoints.Issuer,
			PortalBase:  t.Endpoints.APIBase, // the /ssp app base (v7 has no /ssp-svc)
			ClientID:    t.Endpoints.ClientID,
			RedirectURI: t.Endpoints.RedirectURI,
			Scopes:      t.Endpoints.Scopes,
			HomeState:   t.Policy.HomeState,
		}), nil
	case fake.ID:
		return fake.New(), nil
	default:
		return nil, fmt.Errorf("connectors: no backend registered for connector %q (tenant %q)", t.Connector, t.ID)
	}
}
