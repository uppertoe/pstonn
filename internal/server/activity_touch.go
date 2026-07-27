package server

import (
	"context"
	"log"
	"time"
)

// activityTouchEvery is how often one person's visit is actually written to the
// database. The idle clock is measured in months, so second-level precision is
// worthless — and the store runs on a single SQLite connection shared with the
// scheduler, so a write per request would put page-load latency in contention
// with the reconcile loop for no benefit.
const activityTouchEvery = time.Hour

// touchActivity records that a signed-in person used the app, resetting the idle
// clock on whichever account they act within (their own, or the primary's if they
// are a secondary — either way the household is demonstrably still here).
//
// Best-effort and throttled in memory: a miss costs at most one hour of clock
// precision against a 90-day bound. Losing the cache on restart just means one
// extra write per person per hour.
func (s *Server) touchActivity(ctx context.Context, user string) {
	if user == "" || s.store == nil {
		return
	}
	now := time.Now()
	s.touchMu.Lock()
	if s.lastTouch == nil {
		s.lastTouch = make(map[string]time.Time)
	}
	if last, ok := s.lastTouch[user]; ok && now.Sub(last) < activityTouchEvery {
		s.touchMu.Unlock()
		return
	}
	// Stamp before doing the work: two concurrent requests from the same person
	// should produce one write, and a failed write is not worth retrying on the
	// next request either.
	s.lastTouch[user] = now
	// Bound the map: one entry per person per hour is tiny, but this is keyed by a
	// header-supplied identity, so it must not be able to grow without limit.
	if len(s.lastTouch) > maxLimiterKeys {
		s.lastTouch = map[string]time.Time{user: now}
	}
	s.touchMu.Unlock()

	// The account, not the person: a secondary's visit keeps the primary's session
	// alive, which is the household-level semantics we want.
	_, owner, _ := s.resolveAccount(ctx)
	if owner == "" {
		return
	}
	if err := s.store.TouchAccountActive(ctx, owner); err != nil {
		log.Printf("touch activity for %s: %v", owner, err)
	}
}
