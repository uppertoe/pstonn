package orikan

import (
	"net/http"
	"strings"

	"github.com/uppertoe/pstonn/internal/provider"
)

// This file governs the identity the portal traffic presents.
//
// The identity is split by surface, deliberately:
//
//   - The OIDC login and silent-renew flow (login + auth surfaces) drive the
//     portal's OWN public SPA client through its OWN endpoints, so they present
//     the SPA's request shape — a desktop Chrome identity. This is an authentic
//     replay of the login the browser SPA performs, not a disguise bolted onto
//     something unrelated.
//   - The permit API (api surface) is p.stonn acting with a bearer token, not the
//     browser SPA, so it identifies itself honestly as p.stonn. A datacenter
//     client presenting a browser UA it cannot back up with a browser TLS
//     fingerprint is the strongest bot tell we emit; on the surface that carries
//     the bulk of steady-state traffic we simply stop emitting it.
//
// What this does NOT do, and by policy will not: disguise the TLS fingerprint
// (Go's ClientHello differs from Chrome's), rotate identities, or route through
// proxies. Those are evasion, and on an unauthorised integration they are what
// turns a recoverable soft-block into a deliberate ban. Reducing load and
// identifying honestly help the tenant too; hiding harder does not.
const (
	// honestUA identifies the permit-API traffic as p.stonn, with a URL an operator
	// who sees the traffic can follow to find out what it is — the single biggest
	// thing that turns "unknown bot" into "known, reachable integration".
	honestUA = "p.stonn/1.0 (+https://p.stonn.org; visitor-permit scheduler)"
	// A current desktop Chrome identity for the OIDC surface. The UA and the
	// client-hint headers must describe the SAME browser: a mismatch is itself a
	// bot signal.
	chromeUA         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
	chromeSecUA      = `"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"`
	chromeSecMobile  = "?0"
	chromePlatform   = `"Windows"`
	acceptLanguageAU = "en-AU,en;q=0.9"
)

// surfaceOfPath classifies a portal path for traffic accounting and the login
// sub-limit: the credential flow, session maintenance, or the permit API.
func surfaceOfPath(p string) provider.Surface {
	switch {
	case strings.Contains(p, "/Account/") || p == "/idm" || p == "/idm/":
		return provider.SurfaceLogin // login form GET + credential POST (posts to /idm?returnurl=…)
	case strings.Contains(p, "/connect/"):
		return provider.SurfaceAuth
	case strings.HasPrefix(p, "/ssp-svc/"):
		return provider.SurfaceAPI
	default:
		return provider.SurfaceOther
	}
}

// identityTransport tags every request with its surface (for the generic
// transport's accounting) and presents the surface-appropriate identity.
type identityTransport struct {
	base http.RoundTripper
}

func (t identityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	surface := surfaceOfPath(req.URL.Path)
	req = req.WithContext(provider.WithSurface(req.Context(), surface))
	setIfAbsent(req.Header, "Accept-Language", acceptLanguageAU)
	switch surface {
	case provider.SurfaceLogin, provider.SurfaceAuth:
		setIfAbsent(req.Header, "User-Agent", chromeUA)
		setIfAbsent(req.Header, "sec-ch-ua", chromeSecUA)
		setIfAbsent(req.Header, "sec-ch-ua-mobile", chromeSecMobile)
		setIfAbsent(req.Header, "sec-ch-ua-platform", chromePlatform)
	default:
		setIfAbsent(req.Header, "User-Agent", honestUA)
	}
	return t.base.RoundTrip(req)
}

func setIfAbsent(h http.Header, key, val string) {
	if h.Get(key) == "" {
		h.Set(key, val)
	}
}

// navHeaders shapes a request like a top-level/iframe navigation from the SPA.
func (c *Client) navHeaders(req *http.Request) {
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "iframe")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if c.origin != "" {
		req.Header.Set("Referer", c.origin+"/")
	}
}

// xhrHeaders shapes a request like the SPA's fetch/XHR calls.
func (c *Client) xhrHeaders(req *http.Request) {
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json, text/plain, */*")
	}
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
		req.Header.Set("Referer", c.origin+"/")
	}
}
