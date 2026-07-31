package parking

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// This file governs the identity the council traffic presents, and keeps it from
// hammering the portal when Azure Front Door pushes back.
//
// The identity is split by surface, deliberately (see councilIdentityBrowser):
//
//   - The OIDC login and silent-renew flow (login + auth surfaces) drive the
//     council's OWN public SPA client through its OWN endpoints, so they present
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
// identifying honestly help the council too; hiding harder does not.
const (
	// honestUA identifies the permit-API traffic as p.stonn, with a URL an operator
	// who sees the traffic can follow to find out what it is — the single biggest
	// thing that turns "unknown bot" into "known, reachable integration".
	honestUA = "p.stonn/1.0 (+https://p.stonn.org; visitor-permit scheduler)"

	// A current desktop Chrome identity for the OIDC surface. The UA and the
	// client-hint values MUST agree (a UA that disagrees with sec-ch-ua is itself a
	// bot tell), so bump them together. NOTE: keeping this current is an ongoing
	// cost the honest API surface does not carry — a stale version is a tell, so
	// this is a maintenance treadmill that only exists for the login replay.
	chromeUA         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	chromeSecUA      = `"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"`
	chromeSecMobile  = "?0"
	chromePlatform   = `"Windows"`
	acceptLanguageAU = "en-AU,en;q=0.9"
)

// councilIdentityBrowser reports whether a request path should present the SPA's
// browser identity (login + OIDC surfaces) rather than p.stonn's honest one (the
// permit API). An unrecognised path defaults to the honest identity: only the
// paths we can positively identify as the SPA's own login flow get the costume.
func councilIdentityBrowser(path string) bool {
	switch classifyCouncilPath(path) {
	case "login", "auth":
		return true
	default:
		return false
	}
}

// browserTransport sets the identity headers on every outbound request that does
// not already carry them, so no code path can accidentally ship Go's default
// "Go-http-client/1.1" UA. Which identity depends on the surface (see
// councilIdentityBrowser): the OIDC login flow gets the Chrome UA + sec-ch-ua
// client-hint family; the permit API gets the honest p.stonn UA and NO client
// hints (Chrome client hints under a non-Chrome UA would be the very incoherence
// the split exists to remove). Per-request-class headers (Accept, Sec-Fetch-*,
// Origin, Referer) are still set at the call sites via navHeaders/xhrHeaders.
//
// Note: we deliberately do NOT set Accept-Encoding. Go's transport adds "gzip"
// and transparently decompresses; overriding it (e.g. to add br) would disable
// that automatic decompression and break response parsing.
type browserTransport struct {
	base    http.RoundTripper
	traffic *trafficCounters // nil-safe: counting is skipped when absent (tests)
}

func (t browserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	setIfAbsent(req.Header, "Accept-Language", acceptLanguageAU)
	if councilIdentityBrowser(req.URL.Path) {
		setIfAbsent(req.Header, "User-Agent", chromeUA)
		setIfAbsent(req.Header, "sec-ch-ua", chromeSecUA)
		setIfAbsent(req.Header, "sec-ch-ua-mobile", chromeSecMobile)
		setIfAbsent(req.Header, "sec-ch-ua-platform", chromePlatform)
	} else {
		setIfAbsent(req.Header, "User-Agent", honestUA)
	}
	if t.traffic != nil {
		t.traffic.count(req.URL.Path)
	}
	return t.base.RoundTrip(req)
}

// trafficCounters tallies every outbound council request by kind, so the
// operator can see how often the app actually touches the portal (main logs an
// hourly summary). Counted at the transport so no call path can be missed.
type trafficCounters struct {
	login, auth, api, other atomic.Uint64
}

func (t *trafficCounters) count(path string) {
	switch classifyCouncilPath(path) {
	case "login":
		t.login.Add(1)
	case "auth":
		t.auth.Add(1)
	case "api":
		t.api.Add(1)
	default:
		t.other.Add(1)
	}
}

// classifyCouncilPath buckets a council request path: "login" = the credential
// form flow (interactive link or saved-password reconnect), "auth" = OIDC
// authorize/token (silent renews), "api" = permit reads/writes.
func classifyCouncilPath(p string) string {
	switch {
	case strings.Contains(p, "/Account/") || p == "/idm" || p == "/idm/":
		return "login" // login form GET + credential POST (posts to /idm?returnurl=…)
	case strings.Contains(p, "/connect/"):
		return "auth"
	case strings.HasPrefix(p, "/ssp-svc/"):
		return "api"
	default:
		return "other"
	}
}

// Traffic returns cumulative council request counts since process start.
func (c *Client) Traffic() (login, auth, api, other uint64) {
	return c.traffic.login.Load(), c.traffic.auth.Load(), c.traffic.api.Load(), c.traffic.other.Load()
}

func setIfAbsent(h http.Header, key, val string) {
	if h.Get(key) == "" {
		h.Set(key, val)
	}
}

// navHeaders adds the headers a browser sends on a top-level/iframe navigation
// (used for the authorize GET and the login page), scoped to the portal origin.
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

// xhrHeaders adds the headers a browser sends on a same-origin fetch/XHR (the
// token exchange and the permit API calls), scoped to the portal origin.
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

// ---- per-owner silent-renew serialization (B5) ----

// ownerLock returns the mutex guarding one owner's token/session work, so two
// goroutines (e.g. a reconcile write and a keep-warm pass) can't run concurrent
// silent-renews that rotate the session cookie out from under each other.
func (c *Client) ownerLock(owner string) *sync.Mutex {
	m, _ := c.renewLocks.LoadOrStore(owner, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// ---- per-owner cooldown / backoff on soft blocks (B6) ----

// cooldownFor reports the remaining cooldown for an owner, if any. While in
// cooldown, council calls short-circuit instead of hammering a portal that is
// already pushing back (Azure Front Door 429/403/503), which is how a soft block becomes a
// hard one.
func (c *Client) cooldownFor(owner string) (time.Duration, bool) {
	if v, ok := c.cooldownUntil.Load(owner); ok {
		if d := time.Until(v.(time.Time)); d > 0 {
			return d, true
		}
	}
	return 0, false
}

// penalize records a soft block for the owner and sets an exponential cooldown
// (2, 4, 8, … minutes, capped), honouring a Retry-After hint when present.
func (c *Client) penalize(owner string, retryAfter time.Duration) {
	// Serialised so concurrent penalties can't lose a strike (LoadOrStore+Store
	// alone is a read-modify-write race).
	c.strikeMu.Lock()
	n, _ := c.strikes.LoadOrStore(owner, 0)
	strikes := n.(int) + 1
	c.strikes.Store(owner, strikes)
	c.strikeMu.Unlock()

	backoff := retryAfter
	if backoff <= 0 {
		backoff = time.Duration(1<<min(strikes, 6)) * time.Minute // up to 64m
	}
	if backoff > 2*time.Hour {
		backoff = 2 * time.Hour
	}
	c.cooldownUntil.Store(owner, time.Now().Add(backoff))
}

// clearPenalty resets an owner's backoff after a successful council call.
func (c *Client) clearPenalty(owner string) {
	c.strikes.Delete(owner)
	c.cooldownUntil.Delete(owner)
}

// parseRetryAfter reads a Retry-After header (delta-seconds or HTTP-date form).
func parseRetryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
