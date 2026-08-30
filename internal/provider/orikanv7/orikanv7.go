// Package orikanv7 is the connector for Orikan ePermits v7 — the server-rendered
// generation of the portal, distinct from the Angular SPA + /ssp-svc JSON API that
// internal/provider/orikan drives. Banyule runs it. It is registered as its own
// connector ("orikan-ssp-v7") rather than a parameterisation of orikan-ssp because
// the recon below shows the two are genuinely different products, not two configs
// of one (see docs/council-survey.md).
//
// # Recon (confirmed 2026-08-30, unauthenticated, against Banyule)
//
// Identity (Duende IdentityServer at …/idm, discovery doc):
//   - issuer            https://epermits-ssp.banyule.vic.gov.au/idm
//   - authorize/token   /idm/connect/authorize, /idm/connect/token
//   - the SSP web client's own authorize request:
//     client_id        ePermits.ssp.web.v7
//     response_type    code id_token          (HYBRID — not Stonnington's plain code)
//     response_mode    form_post              (callback is a POST to the redirect_uri)
//     scope            openid profile         (no api scope; there is no token-scoped JSON API)
//     redirect_uri     https://epermits-ssp.banyule.vic.gov.au/ssp/   (the app root itself)
//     PKCE             absent                 (no code_challenge — unlike orikan-ssp)
//   - the /idm login page is standard ASP.NET Identity: a __RequestVerificationToken
//     form POST with a ReturnUrl, the same shape orikan already signs in against.
//
// Permit surface:
//   - /ssp-svc/ → 404. The JSON API orikan-ssp reads and writes DOES NOT EXIST here.
//     The permit list and the vehicle change are the server-rendered MVC app: read
//     by parsing HTML, write by a form POST carrying an anti-forgery token.
//
// # What still needs an authenticated capture (a Banyule test account)
//
// Everything past the login cookie is unknown without a signed-in session, so the
// read/write methods below return ErrNotCaptured until captured. The checklist:
//  1. The hybrid callback: confirm the POST body to /ssp/ (code + id_token), and
//     what session the app sets from it (an ASP.NET auth cookie, its name/lifetime).
//  2. ListPermits: the permits page URL and the HTML shape to parse (permit id,
//     type, number, status, current rego, start/end, whether the type is holder-
//     changeable). v7 tends to be a GridView/partial — capture the container ids.
//  3. SetVehicle: the change-vehicle form — its GET (to read the __RequestVerification
//     token and any hidden state) and its POST (field names for rego and state, the
//     re-read that confirms the change). Whether a permit can be left empty
//     (CanClearVehicle) and whether a registration state is selectable at all.
//  4. Refresh/keep-warm: whether the auth cookie slides like Stonnington's or the
//     IdP's offline_access (which the discovery doc supports) can carry a refresh
//     token instead — the web client does not request it, but a captured flow might.
//
// Until then the descriptor stays enabled:false in the registry, so this connector
// is reachable through connectors.Build (proving the seam) but never scheduled.
package orikanv7

import (
	"context"
	"net/http"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// ID is the connector name a tenant descriptor refers to.
const ID = "orikan-ssp-v7"

// Config parameterises the connector from a tenant descriptor's endpoints.
type Config struct {
	Issuer      string // …/idm
	PortalBase  string // …/ssp — the server-rendered app the permits live in (descriptor api_base)
	ClientID    string // ePermits.ssp.web.v7
	RedirectURI string // …/ssp/ — the form_post callback target
	Scopes      []string
	HomeState   string // the tenant's own registration state code, e.g. "VIC"
}

// Client is an Orikan ePermits v7 backend. Not yet drivable: see the package doc's
// capture checklist. It exists so the descriptor, the registry validation and
// connectors.Build have a real, distinct connector to wire to.
type Client struct {
	cfg  Config
	http *http.Client
}

// New builds the connector on the given transport — the generic client's
// governed, counted RoundTripper, which is the ONLY way this connector may reach
// the portal: taking it here (rather than reaching for http.DefaultClient when the
// capture is filled in) is what keeps the rate governor, traffic accounting and
// the fleet breaker in front of every request. nil means the default transport
// (tests only). New never performs I/O.
func New(cfg Config, tr http.RoundTripper) *Client {
	if tr == nil {
		tr = http.DefaultTransport
	}
	return &Client{cfg: cfg, http: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
}

// The skeleton must satisfy the full contract so the seam compiles today and the
// capture work only fills in method bodies.
var _ provider.Provider = (*Client)(nil)

func (c *Client) ID() string { return ID }

// v7Regions mirrors the Australian state set the SPA connector offers. Whether the
// v7 change-vehicle form actually exposes a state selector is item 3 on the capture
// checklist; the set is declared so the UI is ready either way.
var v7Regions = []provider.Region{
	{Code: "VIC", Label: "VIC"}, {Code: "NSW", Label: "NSW"}, {Code: "ACT", Label: "ACT"},
	{Code: "QLD", Label: "QLD"}, {Code: "SA", Label: "SA"}, {Code: "WA", Label: "WA"},
	{Code: "TAS", Label: "TAS"}, {Code: "NT", Label: "NT"},
}

// Capabilities are the conservative pre-capture defaults: a cookie session that
// must be kept warm (so Refresh IS supported — it is the keep-warm touch, which
// until captured fails loudly with ErrNotCaptured rather than pretending), no
// confirmed clear-to-empty, expiry meaningful (Banyule's permits carry a fixed
// 31 July end date). Revisit once the flow is captured.
func (c *Client) Capabilities() provider.Capabilities {
	return provider.Capabilities{
		CanClearVehicle: false,          // unconfirmed — assume not until the form shows it
		SupportsRefresh: true,           // keep-warm needs it; the web client requests no offline_access
		NeedsKeepWarm:   true,           // ASP.NET auth cookie
		IdleWindow:      10 * time.Hour, // the Duende default, as for orikan-ssp; unmeasured
		SupportsExpiry:  true,
		LoginKind:       "password",
		Regions:         v7Regions,
	}
}

// notCaptured is the honest failure for every op whose wire shape this connector
// has not yet captured. FailUnexpected so that if a descriptor were ever wrongly
// enabled, the operator alert fires loudly rather than the app silently no-op'ing.
func notCaptured(op provider.Op) error {
	return provider.Fail(provider.FailUnexpected, op, provider.ErrNotCaptured)
}

func (c *Client) Login(ctx context.Context, creds provider.Credentials) (provider.Session, error) {
	return nil, notCaptured(provider.OpLogin)
}

func (c *Client) Refresh(ctx context.Context, s *provider.Session) error {
	return notCaptured(provider.OpRefresh)
}

func (c *Client) ListPermits(ctx context.Context, s *provider.Session) ([]provider.Permit, int, error) {
	return nil, 0, notCaptured(provider.OpListPermits)
}

func (c *Client) CurrentVehicle(ctx context.Context, s *provider.Session, p provider.PermitRef) (provider.Vehicle, error) {
	return provider.Vehicle{}, notCaptured(provider.OpReadVehicle)
}

func (c *Client) SetVehicle(ctx context.Context, s *provider.Session, p provider.PermitRef, v provider.Vehicle) error {
	return notCaptured(provider.OpSetVehicle)
}

func (c *Client) ClearVehicle(ctx context.Context, s *provider.Session, p provider.PermitRef) error {
	return notCaptured(provider.OpClearVehicle)
}
