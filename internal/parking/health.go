package parking

// Connector health: a per-tenant success clock over the REAL operations the app
// already performs (keep-warm refreshes, plate reads and writes, logins), plus a
// coarse derived state, surfaced on /status for the external watchdog. Production
// traffic is the probe — no synthetic council transaction is ever made for this.
//
// The derivation is deliberately conservative, because the watchdog turns these
// states into operator email: every alarming state requires either breadth
// (distinct owners) or a structural signal (a login page we cannot parse), so one
// household's wrong password or one glitched response can never raise it. The
// watchdog adds its own persistence threshold on top (a state must hold across
// polls), so a blip that self-heals between polls is never mailed at all.

import (
	"net/http"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// Connector states, ordered here from least to most alarming (see
// WorseConnectorState). The watchdog treats healthy/idle/degraded/rate_limited
// as informational and alerts only on the last three.
const (
	// StateIdle: no operation recently enough to know anything.
	StateIdle = "idle"
	// StateHealthy: the last real council operation succeeded (or failures are
	// below every threshold).
	StateHealthy = "healthy"
	// StateDegraded: several consecutive operations have failed with nothing
	// more specific to say — transient trouble that has not resolved yet.
	StateDegraded = "degraded"
	// StateRateLimited: the edge answered 429 recently.
	StateRateLimited = "rate_limited"
	// StateUpstreamChanged: the portal no longer looks like the portal — a
	// sign-in page we cannot parse, or repeated responses we could not
	// understand. The likeliest signature of a CAPTCHA/flow change.
	StateUpstreamChanged = "upstream_changed"
	// StateAuthFailed: the portal is rejecting logins across DISTINCT owners.
	// One owner's rejection is their password; several at once is the portal.
	StateAuthFailed = "auth_failed"
	// StateBlocked: the fleet breaker is open — a confirmed shared-edge block.
	StateBlocked = "blocked"
)

const (
	// healthSignalWindow is how long an auth-reject / unexpected-shape signal
	// stays live. Long enough that a slow scheduler cadence still accumulates
	// breadth; short enough that yesterday's blip cannot colour today's state.
	healthSignalWindow = 30 * time.Minute
	// healthIdleAfter marks the clock unknown. Keep-warm touches the portal at
	// least every WarmInterval (45m in prod), so a healthy fleet can never look
	// idle; double that keeps one late warm cycle from flapping the state.
	healthIdleAfter = 90 * time.Minute
	// healthAuthRejectOwners: distinct owners whose login must be rejected
	// within the window before the CONNECTOR (not their password) is suspect.
	healthAuthRejectOwners = 2
	// healthUnexpectedOwners: distinct owners whose operations must return an
	// unexpected shape within the window before "possibly a glitch" becomes
	// "possibly a changed API" — the same bar as the scheduler's multi-user-fail
	// operator alert. Owners, not events: one household's odd permit record can
	// answer unreadably on every attempt, and the retry cadence alone would then
	// clear an event count within minutes.
	healthUnexpectedOwners = 2
	// healthDegradedAfter: consecutive failures (with no success in between,
	// across ALL owners) before the state reads degraded.
	healthDegradedAfter = 3
)

// connectorStateRank orders states for aggregation; worse (more alarming) is
// higher. idle ranks below healthy: activity anywhere outweighs silence.
var connectorStateRank = map[string]int{
	StateIdle:            0,
	StateHealthy:         1,
	StateDegraded:        2,
	StateRateLimited:     3,
	StateUpstreamChanged: 4,
	StateAuthFailed:      5,
	StateBlocked:         6,
}

// WorseConnectorState returns the more alarming of two connector states (the
// Mux aggregates per-tenant states with it). An unknown state is treated as
// idle so a typo can only ever under-report.
func WorseConnectorState(a, b string) string {
	if connectorStateRank[b] > connectorStateRank[a] {
		return b
	}
	return a
}

// connectorHealth accumulates the outcome of every real provider operation
// (fed by Client.classify, the single choke point they all pass through).
type connectorHealth struct {
	mu          sync.Mutex
	lastAttempt time.Time
	lastSuccess time.Time
	// consecFails counts operations since the last success, across all owners:
	// on a healthy fleet any owner's keep-warm resets it within minutes, so a
	// climbing value means EVERYTHING is failing, not someone.
	consecFails int
	// authRejects: owner -> when the portal last rejected their login. Distinct
	// owners, because one rejection is a wrong password and several are not.
	// An owner's entry clears on any success of theirs (their credentials work).
	authRejects map[string]time.Time
	// unexpected: owner -> when their operation last returned a shape we could
	// not read (FailUnexpected). Keyed by owner for the same reason authRejects
	// is: the alarm needs breadth, and the same permit failing twice is not it.
	unexpected map[string]time.Time
	// loginShapeAt: the last structurally-unrecognisable sign-in page
	// (ErrLoginFormUnrecognised / ErrLoginOffHost) — deterministic, owner-
	// independent evidence the portal changed, so one occurrence is enough.
	loginShapeAt time.Time
}

// note records one operation's outcome. A context cancellation is ignored
// entirely: the caller gave up (shutdown, a closed page), which says nothing
// about the portal.
func (h *connectorHealth) note(owner string, err error) { h.noteAt(owner, err, time.Now()) }

func (h *connectorHealth) noteAt(owner string, err error, now time.Time) {
	sig := provider.Classify(err)
	if sig.Canceled {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastAttempt = now
	if sig.OK {
		h.lastSuccess = now
		h.consecFails = 0
		delete(h.authRejects, owner) // their credentials demonstrably work
		return
	}
	h.consecFails++
	switch {
	case sig.LoginShape:
		h.loginShapeAt = now
	case sig.LoginRejected:
		if h.authRejects == nil {
			h.authRejects = map[string]time.Time{}
		}
		h.authRejects[owner] = now
	case sig.Unexpected:
		if h.unexpected == nil {
			h.unexpected = map[string]time.Time{}
		}
		h.unexpected[owner] = now
	}
	h.pruneLocked(now)
}

// pruneLocked drops signals that have aged out of the window. Callers hold mu.
func (h *connectorHealth) pruneLocked(now time.Time) {
	for owner, at := range h.authRejects {
		if now.Sub(at) > healthSignalWindow {
			delete(h.authRejects, owner)
		}
	}
	for owner, at := range h.unexpected {
		if now.Sub(at) > healthSignalWindow {
			delete(h.unexpected, owner)
		}
	}
}

// clock returns the raw success clock for Stats.
func (h *connectorHealth) clock() (lastAttempt, lastSuccess time.Time, consecFails int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastAttempt, h.lastSuccess, h.consecFails
}

// state derives the coarse connector state at now, given the breaker's current
// position and the most recent pushback. Priority runs from the most specific
// evidence to the least: a confirmed edge block, then who-changed-what signals,
// then rate limiting, then "we don't know", then plain accumulation.
func (h *connectorHealth) state(now time.Time, breakerOpen bool, lastPB PushbackEvent) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(now)
	recentPB := !lastPB.At.IsZero() && now.Sub(lastPB.At) <= healthSignalWindow
	switch {
	case breakerOpen:
		return StateBlocked
	case len(h.authRejects) >= healthAuthRejectOwners:
		return StateAuthFailed
	case !h.loginShapeAt.IsZero() && now.Sub(h.loginShapeAt) <= healthSignalWindow,
		len(h.unexpected) >= healthUnexpectedOwners:
		return StateUpstreamChanged
	case recentPB && lastPB.Status == http.StatusTooManyRequests:
		return StateRateLimited
	case h.lastAttempt.IsZero() || now.Sub(h.lastAttempt) > healthIdleAfter:
		return StateIdle
	case h.consecFails >= healthDegradedAfter:
		return StateDegraded
	default:
		return StateHealthy
	}
}
