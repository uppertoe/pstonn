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
//
// Build is also where the tenant/connector pairing is checked, once, for every
// tenant in the registry (main builds them all at startup, enabled or not):
//   - the connector must be one this package knows;
//   - a connector that talks to a portal must have been given its endpoints;
//   - the model must be one the app can drive through provider.Provider today —
//     only the plate-writing models have a scheduler (see tenant.Model.Plate), so a
//     coupon or paper tenant cannot be built, let alone reach SetVehicle;
//   - the provider's declared capabilities must be coherent (see
//     provider.Capabilities.Validate).
func Build(t *tenant.Tenant, tr http.RoundTripper) (provider.Provider, error) {
	if !t.Model.Plate() {
		return nil, fmt.Errorf("connectors: tenant %q has model %q, which no connector drives (only plate models schedule through SetVehicle)", t.ID, t.Model)
	}
	var p provider.Provider
	switch t.Connector {
	case orikan.ID:
		if err := needEndpoints(t); err != nil {
			return nil, err
		}
		p = orikan.New(orikan.Config{
			Issuer:      t.Endpoints.Issuer,
			APIBase:     t.Endpoints.APIBase,
			ClientID:    t.Endpoints.ClientID,
			RedirectURI: t.Endpoints.RedirectURI,
			Scopes:      t.Endpoints.Scopes,
			HomeState:   t.Policy.HomeState,
		}, tr)
	case orikanv7.ID:
		if err := needEndpoints(t); err != nil {
			return nil, err
		}
		p = orikanv7.New(orikanv7.Config{
			Issuer:      t.Endpoints.Issuer,
			PortalBase:  t.Endpoints.APIBase, // the /ssp app base (v7 has no /ssp-svc)
			ClientID:    t.Endpoints.ClientID,
			RedirectURI: t.Endpoints.RedirectURI,
			Scopes:      t.Endpoints.Scopes,
			HomeState:   t.Policy.HomeState,
		}, tr)
	case fake.ID:
		p = fake.New()
	default:
		return nil, fmt.Errorf("connectors: no backend registered for connector %q (tenant %q)", t.Connector, t.ID)
	}
	if p.ID() != t.Connector {
		return nil, fmt.Errorf("connectors: %q built a provider that calls itself %q", t.Connector, p.ID())
	}
	if err := p.Capabilities().Validate(); err != nil {
		return nil, fmt.Errorf("connectors: %s (tenant %q): %w", t.Connector, t.ID, err)
	}
	return p, nil
}

// needEndpoints refuses to build a portal connector with nothing to point at. The
// registry already validates the SCHEME of any endpoint given (https only); which
// fields a connector needs is the connector's business, so it is decided here.
func needEndpoints(t *tenant.Tenant) error {
	e := t.Endpoints
	if e.Issuer == "" || e.APIBase == "" || e.ClientID == "" || e.RedirectURI == "" || len(e.Scopes) == 0 {
		return fmt.Errorf("connectors: %s (tenant %q) needs endpoints.issuer, api_base, client_id, redirect_uri and scopes", t.Connector, t.ID)
	}
	return nil
}
