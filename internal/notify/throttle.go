package notify

import (
	"sync"
	"time"
)

// sendLimiter is a small fixed-window per-key throttle, the same shape as the
// per-target limiters the HTTP layer puts in front of invite and guest-link mail
// (see internal/server: inviteTarget, guestLinkTo). It lives here because the
// path it protects has no handler of its own — the scheduler's reconcile loop
// calls it directly — so there is nowhere else to hang the limit.
//
// In-memory and per-process on purpose: a restart resetting the counters is
// acceptable for every use, and the store's single SQLite connection is exactly
// what a throttle must avoid touching.
type sendLimiter struct {
	limit  int
	window time.Duration
	mu     sync.Mutex
	hits   map[string][]time.Time
	calls  int // since the last sweep
}

// Pruning is amortised rather than per-call, and the key count is capped: an
// owner can name arbitrary recipient addresses, so a per-call full scan would
// make the throttle itself the bottleneck under exactly the abuse it exists to
// stop, and an uncapped map would grow with every address tried. On overflow the
// map is cleared outright — crude, but it fails toward "allow" only briefly and
// never toward unbounded memory.
const (
	sendLimiterMaxKeys = 20000
	sendLimiterPrune   = 256
)

func newSendLimiter(limit int, window time.Duration) *sendLimiter {
	return &sendLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

// allow records an event for key and reports whether it is within the limit. A
// nil limiter allows everything: New always builds one, so nil only happens in a
// test that constructs a Service directly, and a throttle must never be the
// reason a notification path panics.
func (l *sendLimiter) allow(key string) bool {
	if l == nil {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = map[string][]time.Time{}
	}
	l.calls++
	if l.calls >= sendLimiterPrune || len(l.hits) > sendLimiterMaxKeys {
		l.calls = 0
		if len(l.hits) > sendLimiterMaxKeys {
			l.hits = map[string][]time.Time{}
		} else {
			for k, ts := range l.hits {
				if kept := keepAfter(ts, cutoff); len(kept) == 0 {
					delete(l.hits, k)
				} else {
					l.hits[k] = kept
				}
			}
		}
	}
	kept := keepAfter(l.hits[key], cutoff)
	if len(kept) >= l.limit {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

// keepAfter drops timestamps that have fallen out of the window.
func keepAfter(ts []time.Time, cutoff time.Time) []time.Time {
	kept := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	return kept
}
