package parking

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// The breaker REACTS to a block; the governor tries to PREVENT one. All 500
// households share this VPS's egress IP, so Azure Front Door may see one client,
// not 500 unrelated browsers — and a rollover or a reconnect storm can put a burst
// of requests on that IP in seconds. The governor bounds the RATE and the
// CONCURRENCY of outbound tenant requests at the transport, the single chokepoint
// every request already passes through (where traffic is counted).
//
// It is a CEILING, not a pacer. The steady-state floor at 500 users is ~10 req/min
// (keep-warm + drift), trivially low in absolute terms; the point is not to throttle
// that baseline but to stop a burst from spiking far above it, and to hold the
// credential-login surface — the most sensitive and the one a reconnect storm
// hammers — to a trickle. When the governor makes a request wait, that request is
// simply spread later; the scheduler's own job-level retry covers anything that
// waits past its context deadline.
//
// Deliberately NOT adaptive yet: an AIMD rate needs production pushback data to tune,
// and we have none. A generous fixed ceiling plus a tight login sub-limit plus a
// concurrency cap is the safe, tunable starting point.
//
// Since it is the SINGLE throughput authority (no separate per-operation pacing —
// see the scheduler, which no longer sleeps between calls), the values below are the
// one knob to turn for a larger fleet. They are the built-in defaults; each is
// overridable via COUNCIL_GOV_* (config.CouncilConfig), and 0/unset falls back here.

// Governor rate defaults (per minute; converted to per-second internally). The
// total sits ~6x above the 500-user floor so it never throttles normal operation;
// the login sub-limit admits one full credential login (~6 requests) at once but
// caps sustained logins so a reconnect storm drains slowly.
const (
	defaultGovTotalPerMin = 60 // global ceiling across every tenant request
	defaultGovTotalBurst  = 10
	defaultGovLoginPerMin = 12 // credential-login surface (/idm, /Account/*)
	defaultGovLoginBurst  = 6
	defaultGovConcurrency = 4 // max simultaneous tenant requests
)

// govOr / govIntOr resolve a configured limit, falling back to the built-in default
// when it is unset or nonsensical (<=0) — the governor must never run wide open.
func govOr(v, def int) float64 {
	if v <= 0 {
		return float64(def)
	}
	return float64(v)
}

func govIntOr(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// tokenBucket is a lazy token bucket: tokens accrue at perSec up to burst, and a
// request takes one. The clock is passed in so the core is deterministic under test.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	burst  float64
	perSec float64
	last   time.Time
}

func newTokenBucket(perMin, burst float64) *tokenBucket {
	return &tokenBucket{tokens: burst, burst: burst, perSec: perMin / 60}
}

// tryTake takes one token if available at `now`, reporting success or, on failure,
// how long until one accrues.
func (tb *tokenBucket) tryTake(now time.Time) (ok bool, wait time.Duration) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if !tb.last.IsZero() && now.After(tb.last) {
		tb.tokens = math.Min(tb.burst, tb.tokens+now.Sub(tb.last).Seconds()*tb.perSec)
	}
	tb.last = now
	if tb.tokens >= 1 {
		tb.tokens--
		return true, 0
	}
	if tb.perSec <= 0 {
		return false, time.Hour // effectively closed; shouldn't happen with sane config
	}
	need := (1 - tb.tokens) / tb.perSec
	return false, time.Duration(need * float64(time.Second))
}

// wait blocks until a token is available or ctx is done.
func (tb *tokenBucket) wait(ctx context.Context) error {
	for {
		ok, d := tb.tryTake(time.Now())
		if ok {
			return nil
		}
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// governor combines per-surface rate ceilings with a global concurrency cap.
type governor struct {
	total *tokenBucket  // ceiling across all tenant requests
	login *tokenBucket  // sub-limit for the credential-login surface
	conc  chan struct{} // concurrency permits
}

func newGovernor(totalPerMin, totalBurst, loginPerMin, loginBurst float64, concurrency int) *governor {
	if concurrency < 1 {
		concurrency = 1
	}
	return &governor{
		total: newTokenBucket(totalPerMin, totalBurst),
		login: newTokenBucket(loginPerMin, loginBurst),
		conc:  make(chan struct{}, concurrency),
	}
}

// loginFlowRequests is how many login-surface requests one full credential login
// makes (form GET, password POST, the IdP redirects and the token exchange) — the
// same "~6" the login burst is sized to admit at once.
const loginFlowRequests = 6

// loginBudget is the WORST-CASE time the governor may hold one full credential
// login before its last request is admitted: both buckets empty, and every request
// waiting for a token to accrue in the login sub-limit and then in the total.
// Zero for a nil governor. Rate-limit waits only — the concurrency slot and the
// network are the caller's to budget separately.
//
// It exists so a caller can size a deadline around the governor instead of under
// it. The reconnect worker used to hand every login a flat 20s: once a burst of
// back-to-back reconnects had drained the login bucket, the next login spent its
// whole deadline waiting for tokens and was cancelled mid-flow — a half-completed
// IdP authentication, the worst possible outcome of a timeout, from a wait the
// governor itself had imposed.
func (g *governor) loginBudget() time.Duration {
	if g == nil {
		return 0
	}
	perRequest := func(tb *tokenBucket) time.Duration {
		if tb == nil || tb.perSec <= 0 {
			return 0
		}
		return time.Duration(float64(time.Second) / tb.perSec)
	}
	return time.Duration(loginFlowRequests) * (perRequest(g.login) + perRequest(g.total))
}

// acquire blocks until this request may proceed under both the rate ceilings and
// the concurrency cap, returning a release for the concurrency slot. A nil governor
// is a no-op (feature disabled / tests). Rate is taken BEFORE a concurrency slot so
// a rate-limited request does not hold a slot other requests need.
func (g *governor) acquire(ctx context.Context, surface provider.Surface) (release func(), err error) {
	if g == nil {
		return func() {}, nil
	}
	// The login surface pays into BOTH its own sub-limit and the total, so it can
	// never exceed either. Everything else pays into the total only.
	if surface == provider.SurfaceLogin {
		if err := g.login.wait(ctx); err != nil {
			return nil, err
		}
	}
	if err := g.total.wait(ctx); err != nil {
		return nil, err
	}
	select {
	case g.conc <- struct{}{}:
		return func() { <-g.conc }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
