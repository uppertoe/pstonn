package orikan

import (
	"sync"
	"time"
)

// authCircuit is a per-tenant circuit breaker for the AUTH surface only — the
// prompt=none authorize that mints/slides tokens (authorizeWithCookie). It exists
// because a council-side auth outage (the IdentityServer returning 5xx) is otherwise
// re-hit by every path that needs a token — keep-warm renews AND every API op whose
// cached token has gone stale — at each path's natural rate, for as long as the
// outage lasts.
//
// It is deliberately scoped to authorize, NOT to the whole council client: the
// permit API (/ssp-svc) stays healthy in an auth-only outage, so an API op holding a
// still-valid cached token never reaches authorize and is never gated — due schedule
// changes keep applying. Only an op that actually needs a fresh token hits the gate.
//
// When open it admits ONE probe at a time, and the wait before the next probe BACKS
// OFF exponentially (authProbeBase → ×2 → authProbeMax). A fixed fast probe over a
// multi-hour outage would be a persistent, low-value knock on a server that is down —
// the escalating wait means a long outage settles to a rare probe (~one per
// authProbeMax) rather than a steady drumbeat, while a quick blip still recovers on
// the first short probe. A successful authorize (the upstream is serving again, or
// it served a genuine session-expiry — which is itself proof it is up) resets it.
const (
	// authTripThreshold is how many upstream authorize failures SINCE THE LAST SUCCESS
	// open the circuit. A success (a code, or a genuine expiry — proof the IdP served)
	// resets the count; an inconclusive result (edge push-back / an odd redirect) is
	// deliberately NEUTRAL — it neither counts nor resets. Neutral, not resetting,
	// because an edge 503 interleaved with genuine origin 500s must not keep re-arming
	// the count and leave us hammering a down origin; the edge is the fleet breaker's
	// job. >1 so a single transient 5xx does not gate; low so a real outage (many
	// owners' renews failing in seconds) opens promptly.
	authTripThreshold = 3
	authProbeBase     = 1 * time.Minute
	authProbeMax      = 15 * time.Minute
)

type authCircuit struct {
	mu        sync.Mutex
	fails     int       // upstream failures since the last success while closed (→ open at the threshold); inconclusive results are neutral
	openUntil time.Time // when open, the earliest the next probe may go; zero = closed
	backoff   time.Duration
	probing   bool // a half-open probe is in flight; no other authorize may proceed
}

// allow reports whether an authorize may proceed now. `probe` marks the single
// half-open request permitted to test recovery; the caller MUST pass it back to the
// matching outcome method so the in-flight-probe flag is cleared. `retry` is how long
// until the next attempt is permitted, for the caller's fast-fail message.
//
//	closed              → (false, true, 0)
//	open, probe in-flight→ (false, false, remaining|~backoff) [one probe at a time]
//	open, waiting        → (false, false, remaining)
//	open, probe due      → (true,  true, 0)             [admit the probe]
func (a *authCircuit) allow(now time.Time) (probe, ok bool, retry time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.openUntil.IsZero() {
		return false, true, 0
	}
	if a.probing {
		// A probe is in flight and, being past openUntil, remaining is ~0 — reporting
		// "retry in 0s" would wrongly invite an immediate retry. Surface the cycle
		// length instead: the caller should check back after the probe resolves.
		if r := a.remainingLocked(now); r > 0 {
			return false, false, r
		}
		return false, false, a.backoff
	}
	if now.Before(a.openUntil) {
		return false, false, a.openUntil.Sub(now)
	}
	a.probing = true
	return true, true, 0
}

func (a *authCircuit) remainingLocked(now time.Time) time.Duration {
	if d := a.openUntil.Sub(now); d > 0 {
		return d
	}
	return 0
}

// onUpstreamFailure records an authorize that reached the council and got a 5xx or a
// transport error — the "upstream is down" signal. A probe failure escalates the
// backoff; a closed-admitted failure counts toward the trip threshold and opens the
// circuit once reached.
func (a *authCircuit) onUpstreamFailure(now time.Time, wasProbe bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if wasProbe {
		a.probing = false
		a.backoff *= 2
		if a.backoff > authProbeMax {
			a.backoff = authProbeMax
		}
		a.openUntil = now.Add(a.backoff)
		return
	}
	if !a.openUntil.IsZero() {
		return // already open; a request admitted before the open just confirms it
	}
	a.fails++
	if a.fails >= authTripThreshold {
		a.backoff = authProbeBase
		a.openUntil = now.Add(a.backoff)
	}
}

// onSuccess records a successful authorize (a code, or a genuine session-expiry — the
// upstream is serving either way), closing the circuit and clearing the streak.
func (a *authCircuit) onSuccess(wasProbe bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if wasProbe {
		a.probing = false
	}
	a.fails = 0
	a.openUntil = time.Time{}
	a.backoff = 0
}

// onInconclusive records an authorize that reached the council but was NOT an
// upstream-down signal and NOT a clean success — edge push-back (429/403/503, which
// the fleet breaker owns), an odd 4xx, or an unrecognised redirect. It does not
// count toward the auth trip and does not escalate; it only clears the probe flag
// and re-arms the current wait so the circuit neither closes nor tightens on it.
func (a *authCircuit) onInconclusive(now time.Time, wasProbe bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if wasProbe {
		a.probing = false
		if !a.openUntil.IsZero() {
			a.openUntil = now.Add(a.backoff)
		}
	}
}

// state reports whether the circuit is open and how long until the next probe, for
// the connector-health surface (/status).
func (a *authCircuit) state(now time.Time) (open bool, retry time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.openUntil.IsZero() {
		return false, 0
	}
	return true, a.remainingLocked(now)
}
