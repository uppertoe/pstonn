package parking

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// This file makes the council traffic look like a normal browser and keeps it
// from hammering the portal when Akamai pushes back. It does NOT disguise the
// TLS fingerprint (Go's ClientHello differs from Chrome's); that is a known
// residual risk to revisit if the login path is ever challenged.

// A current desktop Chrome identity. The header set and the client-hint values
// are kept mutually consistent (a UA that disagrees with sec-ch-ua is itself a
// bot tell). Bump these together periodically so they don't age conspicuously.
const (
	chromeUA         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	chromeSecUA      = `"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"`
	chromeSecMobile  = "?0"
	chromePlatform   = `"Windows"`
	acceptLanguageAU = "en-AU,en;q=0.9"
)

// browserTransport sets the invariant browser headers (User-Agent, language, and
// the sec-ch-ua client-hint family) on every outbound request that does not
// already carry them, so no code path can accidentally ship Go's default
// "Go-http-client/1.1" UA. Per-request-class headers (Accept, Sec-Fetch-*,
// Origin, Referer) are set at the call sites via navHeaders/xhrHeaders.
//
// Note: we deliberately do NOT set Accept-Encoding. Go's transport adds "gzip"
// and transparently decompresses; overriding it (e.g. to add br) would disable
// that automatic decompression and break response parsing.
type browserTransport struct{ base http.RoundTripper }

func (t browserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	setIfAbsent(req.Header, "User-Agent", chromeUA)
	setIfAbsent(req.Header, "Accept-Language", acceptLanguageAU)
	setIfAbsent(req.Header, "sec-ch-ua", chromeSecUA)
	setIfAbsent(req.Header, "sec-ch-ua-mobile", chromeSecMobile)
	setIfAbsent(req.Header, "sec-ch-ua-platform", chromePlatform)
	return t.base.RoundTrip(req)
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
// already pushing back (Akamai 429/403/503), which is how a soft block becomes a
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
	n, _ := c.strikes.LoadOrStore(owner, 0)
	strikes := n.(int) + 1
	c.strikes.Store(owner, strikes)

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
