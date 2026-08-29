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
// CONCURRENCY of outbound council requests at the transport, the single chokepoint
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
	defaultGovTotalPerMin = 60 // global ceiling across every council request
	defaultGovTotalBurst  = 10
	defaultGovLoginPerMin = 12 // credential-login surface (/idm, /Account/*)
	defaultGovLoginBurst  = 6
	defaultGovConcurrency = 4 // max simultaneous council requests
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
	total *tokenBucket  // ceiling across all council requests
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
