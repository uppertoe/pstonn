package orikan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// ---- push-back ----

// pushback returns the typed unavailable error when the response is edge/rate-limit
// push-back (429/403/503); nil otherwise. For the permit API the caller first
// separates a JSON 403 (a genuine refusal) from an HTML one (push-back).
func pushback(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusForbidden, http.StatusServiceUnavailable:
		path := ""
		if resp.Request != nil && resp.Request.URL != nil {
			path = resp.Request.URL.Path
		}
		return &provider.Unavailable{
			RetryAfter:  parseRetryAfter(resp),
			Status:      resp.StatusCode,
			Surface:     surfaceOfPath(path),
			ContentType: safeExcerpt(resp.Header.Get("Content-Type")),
			Ref:         safeExcerpt(resp.Header.Get("X-Azure-Ref")),
		}
	}
	return nil
}

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

// ---- permit API ----

// maxAPIBody bounds a permit-API JSON response. The real ones are a few
// kilobytes; the bound exists so a hostile or broken portal cannot make a decode
// consume memory in proportion to what it chooses to send.
const maxAPIBody = 1 << 20

// drainClose discards (a bounded amount of) the body and closes it, so the
// keep-alive connection is reusable.
func drainClose(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
}

// refusalPayload is the portal's refusal body: a JSON ARRAY of message objects,
// e.g. [{"Level":0,"Message":"Vehicle Registration has invalid pattern","ID":null,…}]
// (captured live 2026-07-31 from a rejected manageVehicle POST).
type refusalPayload struct {
	Message       string `json:"Message"`
	CustomMessage string `json:"CustomMessage"`
}

// refusalMessage extracts a human-readable reason from a refusal body, or "" if
// there is nothing usable. Portal-controlled text: passed through safeExcerpt.
// Multiple messages are joined: the portal reports per-field validation, and
// showing only the first would hide the rest of what the user has to fix.
func refusalMessage(body []byte) string {
	var payload []refusalPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	var msgs []string
	for _, p := range payload {
		m := p.CustomMessage // the portal's own user-facing wording, when it sets one
		if strings.TrimSpace(m) == "" {
			m = p.Message
		}
		if m = strings.TrimSpace(m); m != "" {
			msgs = append(msgs, m)
		}
	}
	if len(msgs) == 0 {
		return ""
	}
	return safeExcerpt(strings.Join(msgs, "; "))
}

// isJSONResponse reports whether the response declares a JSON body — the shape
// the API itself speaks, as opposed to an edge HTML challenge page.
func isJSONResponse(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "json")
}

// apiRequest issues an authenticated request to the permit API. It classifies
// edge push-back (429/403-HTML/503) as *provider.Unavailable, a mid-life token
// rejection (401) is retried once after a forced renew, and any other non-2xx is
// a classified provider.Error carrying the portal's own reason when it gave one.
// A 2xx returns the response for the caller to decode.
func (c *Client) apiRequest(ctx context.Context, ss *session, method, path string, op provider.Op, query url.Values, body []byte) (*http.Response, error) {
	at, err := c.accessToken(ctx, ss, false)
	if err != nil {
		return nil, err
	}
	resp, err := c.doAPI(ctx, at, method, path, query, body)
	if err != nil {
		// Transport error (DNS, dial, timeout, reset): transient by nature.
		return nil, provider.Fail(provider.FailTransient, op, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// The cached token was rejected mid-life (the portal can kick a session
		// server-side, e.g. when the user logs into the portal in a browser).
		// Force one silent-renew and retry; if the renew itself fails the error
		// (ErrSessionExpired, Unavailable, …) flows out.
		drainClose(resp)
		at, err = c.accessToken(ctx, ss, true)
		if err != nil {
			return nil, err
		}
		resp, err = c.doAPI(ctx, at, method, path, query, body)
		if err != nil {
			return nil, provider.Fail(provider.FailTransient, op, err)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			// A freshly-minted token is still refused: not a stale-token blip.
			drainClose(resp)
			return nil, provider.Fail(provider.FailRejected, op, errors.New("portal rejected a fresh access token (401)"))
		}
	}
	switch resp.StatusCode {
	case http.StatusForbidden:
		// Two very different things arrive as 403: edge push-back (an HTML challenge
		// page — transient, back off) and a genuine API refusal (JSON, e.g. permit
		// access revoked — durable, will never self-heal).
		if isJSONResponse(resp) {
			drainClose(resp)
			return nil, provider.Fail(provider.FailRejected, op, errors.New("the portal refused access (403)"))
		}
		fallthrough
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		busy := pushback(resp)
		drainClose(resp)
		return nil, busy
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// The client never follows redirects, and the permit API never issues one:
		// a bearer-authenticated JSON endpoint answers with data or an error. A 3xx
		// here is therefore the EDGE speaking — a WAF interstitial, a maintenance
		// bounce, a portal relocation — and says nothing about this household's
		// permit. Left to the generic rule below it would classify as a refusal
		// (a 4xx-like "< 500"), which the scheduler parks for good and reports to
		// the household as the council not letting p.stonn make the change.
		// Transient instead: retried on the backoff path, and if the redirect
		// persists it surfaces as a degraded connector, not a parked permit.
		loc := resp.Header.Get("Location")
		drainClose(resp)
		return nil, provider.Fail(provider.FailTransient, op, fmt.Errorf("portal redirected (%d) to %s: edge interstitial or portal moved?", resp.StatusCode, redirectTarget(loc)))
	}
	// Other non-2xx: 5xx is a server-side blip (transient); 4xx is a refusal.
	// A refusal usually carries the portal's OWN reason, and it is the only thing
	// that can tell a user what to actually do — "Vehicle Registration has invalid
	// pattern" is actionable where "returned 400" is not. Read it before discarding.
	errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	drainClose(resp)
	kind := provider.FailRejected
	if resp.StatusCode >= 500 {
		kind = provider.FailTransient
	}
	if msg := refusalMessage(errBody); msg != "" {
		return nil, provider.FailDetail(kind, op, msg, fmt.Errorf("the portal refused it: %s (%d)", msg, resp.StatusCode))
	}
	return nil, provider.Fail(kind, op, fmt.Errorf("portal returned %d", resp.StatusCode))
}

// doAPI issues one authenticated permit-API request. Body is bytes (not a
// Reader) so the 401 path can replay it.
func (c *Client) doAPI(ctx context.Context, at, method, path string, query url.Values, body []byte) (*http.Response, error) {
	u := c.apiBase + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+at)
	req.Header.Set("Content-Type", "application/json")
	c.xhrHeaders(req)
	return c.do(req)
}

// Do issues one authenticated raw permit-API request for the session (minting a
// token if needed) and returns the undecoded response, so a capture reports what
// the portal actually sent rather than what this provider's structs keep.
func (c *Client) Do(ctx context.Context, s *provider.Session, method, path string, query url.Values, body []byte) (*http.Response, error) {
	ss, err := load(s)
	if err != nil {
		return nil, err
	}
	at, err := c.accessToken(ctx, ss, false)
	if err != nil {
		return nil, err
	}
	resp, err := c.doAPI(ctx, at, method, path, query, body)
	if serr := save(s, ss); serr != nil && err == nil {
		err = serr
	}
	return resp, err
}
