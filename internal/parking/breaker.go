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

	threshold     int           // distinct owners pushed back within window to open
	window        time.Duration // how far back the distinct-owner tally reaches
	cooldown      time.Duration // how long the circuit stays open once tripped
	probeInterval time.Duration // half-open: at most one probe per this interval
}

func newBreaker(threshold int, window, cooldown, probeInterval time.Duration) *breaker {
	return &breaker{
		threshold:     threshold,
		window:        window,
		cooldown:      cooldown,
		probeInterval: probeInterval,
	}
}

// allow reports whether a council request may proceed now, and if not, how long
// to back off. When the open window has elapsed it lets a SINGLE request through
// as a half-open probe (nudging openUntil forward by probeInterval so concurrent
// callers don't all probe at once); the probe's own success or pushback then
// closes or re-opens the circuit through onSuccess / onPushback. A nil breaker is
// always-allow, so the feature can be disabled by leaving it unset.
func (b *breaker) allow(now time.Time) (ok bool, wait time.Duration) {
	if b == nil {
		return true, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.IsZero() {
		return true, 0 // closed
	}
	if now.Before(b.openUntil) {
		return false, b.openUntil.Sub(now) // open: paused
	}
	// Half-open: the open window has elapsed. Let this one through as a probe, but
	// hold the line for probeInterval so a burst of waiting callers doesn't all
	// stampede the edge the instant the window lifts.
	b.openUntil = now.Add(b.probeInterval)
	return true, 0
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
		b.openUntil = now.Add(cd)
	}
	return b.blockedLocked(now) && !wasBlocked
}

// blockedLocked reports whether the circuit is pausing traffic right now (open, or
// mid-cooldown). Caller holds b.mu.
func (b *breaker) blockedLocked(now time.Time) bool {
	return !b.openUntil.IsZero() && now.Before(b.openUntil)
}

// onSuccess is called after a clean council response. When the circuit is open or
// half-open, a success means the edge is serving us again, so it closes and clears
// the tally — the half-open probe's happy path. When closed it just drops the
// owner from the tally, so isolated single-owner blips age out instead of
// accumulating toward the threshold.
// onSuccess returns closedNow=true only when this success brought a paused-or-
// probing circuit back to fully closed, so the caller can log the resume once.
func (b *breaker) onSuccess(now time.Time, owner string) (closedNow bool) {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.recent, owner)
	wasSet := !b.openUntil.IsZero()
	b.openUntil = time.Time{}
	return wasSet
}

// breakerGate returns ErrCouncilBusy when the fleet circuit is open, for use at
// every council entry point. Nil when traffic may proceed (including the half-open
// probe, whose slot allow() consumes). Kept separate from the per-owner cooldown
// check so the two compose: an owner passes only when neither is blocking.
func (c *Client) breakerGate() error {
	if open, wait := c.breaker.allow(time.Now()); !open {
		return fmt.Errorf("%w: the council edge is blocking our address; paused for %s", ErrCouncilBusy, wait.Round(time.Second))
	}
	return nil
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
