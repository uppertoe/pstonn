package parking

import (
	"fmt"
	"sync"
	"time"
)

// Breaker defaults. Tuned for the shared-IP failure: three distinct owners pushed
// back inside two minutes is well past coincidence at fleet scale but forgiving of
// one account's isolated trouble, and a five-minute pause with a single 30s probe
// gives an Azure-Front-Door rate window room to reset without stampeding it.
const (
	defaultBreakerThreshold = 3
	defaultBreakerWindow    = 2 * time.Minute
	defaultBreakerCooldown  = 5 * time.Minute
	defaultBreakerProbe     = 30 * time.Second
	// maxBreakerCooldown caps how long a single pushback can pause the WHOLE fleet.
	// The edge's Retry-After floors the cooldown (so we honour a real backoff), but
	// uncapped it is a fleet-wide, restart-surviving outage from one response header:
	// Azure Front Door can legitimately send Retry-After: 86400 on a 429/503, which
	// would otherwise pause all council traffic for a day. The half-open probe then
	// re-checks every probeInterval, so a still-live block simply re-opens.
	maxBreakerCooldown = 30 * time.Minute
)

// The per-owner cooldown (penalize/cooldownFor) protects ONE account's session
// from being hammered while the council is refusing it. It is the wrong tool for
// the failure that matters at fleet scale: Azure Front Door throttles by source
// IP, and every owner shares this one egress IP. When the edge blocks the IP,
// each owner's request independently hits the same wall, so 500 owners would
// "learn" the outage one at a time — each strike hammering an edge that is already
// refusing us, which is exactly how a soft block escalates to a hard one.
//
// The breaker is the fleet-level counterpart: several DISTINCT owners pushed back
// inside a short window is the signature of an IP-level block (as opposed to one
// account's permit being revoked), so it opens a SHARED circuit and pauses all
// council traffic at once. It half-opens after a cooldown and lets a single probe
// test the water before resuming, so recovery doesn't stampede the edge.
type breaker struct {
	mu        sync.Mutex
	openUntil time.Time            // while now < this, all council traffic is paused
	recent    map[string]time.Time // owner -> last pushback, for the distinct-owner tally
	// generation is bumped every time the circuit (re)opens. A permit carries the
	// generation it was admitted under; a success can only close the circuit if its
	// permit is the half-open probe AND still on the current generation. That is
	// what stops a request admitted while CLOSED, but returning after the circuit
	// opened, from wrongly closing it — its 200 says nothing about the block having
	// cleared.
	generation uint64

	lastPushback time.Time // most recent pushback, for persistence/diagnostics

	threshold     int           // distinct owners pushed back within window to open
	window        time.Duration // how far back the distinct-owner tally reaches
	cooldown      time.Duration // how long the circuit stays open once tripped
	probeInterval time.Duration // half-open: at most one probe per this interval
}

// breakerPermit is handed back by allow() and presented again at onSuccess so the
// breaker can tell the ONE half-open probe apart from every other in-flight
// request. Only the probe, still on the generation it was admitted under, may
// close an open circuit.
type breakerPermit struct {
	probe bool   // admitted AS the half-open probe (not merely while closed)
	gen   uint64 // the open-episode generation at admission
}

func newBreaker(threshold int, window, cooldown, probeInterval time.Duration) *breaker {
	return &breaker{
		threshold:     threshold,
		window:        window,
		cooldown:      cooldown,
		probeInterval: probeInterval,
	}
}

// allow reports whether a council request may proceed now, and if not, how long to
// back off. It returns a permit the caller must present to onSuccess. When the open
// window has elapsed it admits a SINGLE request as the half-open probe (nudging
// openUntil forward by probeInterval so concurrent callers don't all probe at
// once). A nil breaker is always-allow, so the feature disables by staying unset.
func (b *breaker) allow(now time.Time) (permit breakerPermit, ok bool, wait time.Duration) {
	if b == nil {
		return breakerPermit{}, true, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.IsZero() {
		return breakerPermit{gen: b.generation}, true, 0 // closed
	}
	if now.Before(b.openUntil) {
		return breakerPermit{}, false, b.openUntil.Sub(now) // open: paused
	}
	// Half-open: the open window has elapsed. Admit this one as the probe, but hold
	// the line for probeInterval so a burst of waiting callers doesn't all stampede
	// the edge the instant the window lifts.
	b.openUntil = now.Add(b.probeInterval)
	return breakerPermit{probe: true, gen: b.generation}, true, 0
}

// onPushback records that owner was pushed back and opens (or re-opens) the
// circuit when enough DISTINCT owners have been pushed back within the window —
// the signal that the block is at the shared edge, not one account. A pushback
// while half-open (a failed probe) also re-opens it, because openUntil is then in
// the near future. retryAfter, when the edge supplied one, floors the cooldown.
// onPushback returns openedNow=true only when THIS pushback transitioned the
// circuit from serving to paused, so the caller can log the fleet-pause event once
// rather than on every strike.
func (b *breaker) onPushback(now time.Time, owner string, retryAfter time.Duration) (openedNow bool) {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	wasBlocked := b.blockedLocked(now)
	b.lastPushback = now
	if b.recent == nil {
		b.recent = make(map[string]time.Time)
	}
	b.recent[owner] = now
	distinct := 0
	for o, t := range b.recent {
		if now.Sub(t) > b.window {
			delete(b.recent, o)
			continue
		}
		distinct++
	}
	if distinct >= b.threshold || wasBlocked {
		cd := b.cooldown
		if retryAfter > cd {
			cd = retryAfter
		}
		if cd > maxBreakerCooldown {
			cd = maxBreakerCooldown // never let one header pause the whole fleet for hours
		}
		b.openUntil = now.Add(cd)
		// A fresh open episode: invalidate any probe permit admitted under the old
		// generation, so a slow probe that is about to fail cannot later close a
		// circuit that has since re-opened.
		b.generation++
	}
	return b.blockedLocked(now) && !wasBlocked
}

// blockedLocked reports whether the circuit is pausing traffic right now (open, or
// mid-cooldown). Caller holds b.mu.
func (b *breaker) blockedLocked(now time.Time) bool {
	return !b.openUntil.IsZero() && now.Before(b.openUntil)
}

// onSuccess is called after a clean council response, presenting the permit allow()
// handed out. It always drops the owner from the tally (so isolated single-owner
// blips age out instead of accumulating toward the threshold). It CLOSES an open
// circuit only when the permit is the designated half-open probe AND still on the
// current generation — never on an ordinary success. A request admitted while the
// circuit was closed but returning after it opened carries probe=false, and a probe
// from a superseded open episode carries a stale generation; neither may close the
// circuit, because a 200 from before (or unrelated to) the block proves nothing
// about the block having cleared. Returns closedNow=true only on the transition, so
// the caller logs the resume once.
func (b *breaker) onSuccess(now time.Time, owner string, permit breakerPermit) (closedNow bool) {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.recent, owner)
	if b.openUntil.IsZero() {
		return false // already closed; nothing to resume
	}
	if permit.probe && permit.gen == b.generation {
		b.openUntil = time.Time{}
		return true
	}
	return false
}

// breakerGate is the fleet-circuit check at a council entry point. It returns the
// permit to present at the eventual success, and ErrCouncilBusy when the circuit is
// open. Kept separate from the per-owner cooldown check so the two compose: an owner
// passes only when neither is blocking.
//
// Gate ONCE per logical operation (apiRequest, warmLocked, Link), not per HTTP
// request: an operation's internal renew must not take a second permit, or during
// half-open the operation's own gate would consume the single probe slot and then
// block its renew. The success is reported at the operation level with this permit;
// the shared authorize step does not touch the breaker.
func (c *Client) breakerGate() (breakerPermit, error) {
	permit, ok, wait := c.breaker.allow(time.Now())
	if !ok {
		return permit, fmt.Errorf("%w: the council edge is blocking our address; paused for %s", ErrCouncilBusy, wait.Round(time.Second))
	}
	return permit, nil
}

// snapshot returns the persistable state (the open deadline, last pushback, and
// generation), so a restart can resume from the real pause rather than a clean
// slate. Zero openUntil means closed.
func (b *breaker) snapshot() (openUntil, lastPushback time.Time, generation uint64) {
	if b == nil {
		return time.Time{}, time.Time{}, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.openUntil, b.lastPushback, b.generation
}

// restore seeds the breaker from persisted state on boot. It adopts openUntil ONLY
// if it is still in the future — a pause a restart must not clear — and always
// carries the generation forward so it stays monotonic across restarts. An expired
// or absent pause leaves the breaker closed.
func (b *breaker) restore(openUntil, lastPushback time.Time, generation uint64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if openUntil.After(time.Now()) {
		b.openUntil = openUntil
	}
	b.lastPushback = lastPushback
	if generation > b.generation {
		b.generation = generation
	}
}

// state reports whether the circuit is open right now and the remaining pause, for
// the operator status line.
func (b *breaker) state(now time.Time) (open bool, wait time.Duration) {
	if b == nil {
		return false, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.IsZero() || !now.Before(b.openUntil) {
		return false, 0
	}
	return true, b.openUntil.Sub(now)
}
