package parking

import (
	"log"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// PushbackEvent is a privacy-safe diagnostic snapshot of the last time the tenant
// edge refused us (a 403 HTML challenge, 429, or 503). If we are ever blocked, this
// is what tells us WHICH control fired — a rate limit, a bot rule, a managed WAF
// rule, or platform throttling — since the client cannot see the edge's config.
// The X-Azure-Ref correlation id is the single most useful field: it is what the
// tenant (or Microsoft) would look the incident up by.
type PushbackEvent struct {
	At          time.Time
	Surface     string // login / auth / api
	Status      int
	ContentType string
	RetryAfter  time.Duration
	AzureRef    string // X-Azure-Ref: the Azure Front Door correlation id
}

// recordPushback captures the diagnostic fields of an edge refusal (as the
// provider classified it) and logs them, so an operator can quote the edge's own
// correlation id back to the tenant.
func (c *Client) recordPushback(u *provider.Unavailable) {
	ev := PushbackEvent{
		At:          time.Now(),
		Surface:     string(u.Surface),
		Status:      u.Status,
		ContentType: u.ContentType,
		RetryAfter:  u.RetryAfter,
		AzureRef:    u.Ref,
	}
	c.traffic.pbMu.Lock()
	c.traffic.lastPB = ev
	c.traffic.pbMu.Unlock()
	log.Printf("parking: council pushback %s %d (content-type=%q retry-after=%s x-azure-ref=%q)",
		ev.Surface, ev.Status, ev.ContentType, ev.RetryAfter.Round(time.Second), ev.AzureRef)
}

type rollingCounter struct {
	mu      sync.Mutex
	buckets []minuteBucket // ring indexed by wall-clock minute
}

// minuteBucket holds one minute's count, tagged with the minute it belongs to so a
// stale slot (the same ring index, a full cycle later) is recognised and reset
// rather than double-counted.
type minuteBucket struct {
	epoch int64 // unix minute this slot is counting
	n     int
}

// newRollingCounter tracks the last `minutes` minutes. Size it to the widest
// window ever queried (5m here, with headroom).
func newRollingCounter(minutes int) *rollingCounter {
	return &rollingCounter{buckets: make([]minuteBucket, minutes)}
}

func (r *rollingCounter) add(now time.Time) {
	if r == nil {
		return
	}
	m := now.Unix() / 60
	r.mu.Lock()
	b := &r.buckets[int(m)%len(r.buckets)]
	if b.epoch != m {
		b.epoch, b.n = m, 0 // this slot was last used a full cycle ago; reset it
	}
	b.n++
	r.mu.Unlock()
}

// window sums the counts recorded in the last `minutes` minutes (including the
// current, partial minute). Slots whose epoch has aged out of the window are
// skipped, so no explicit expiry sweep is needed.
func (r *rollingCounter) window(now time.Time, minutes int) int {
	if r == nil {
		return 0
	}
	m := now.Unix() / 60
	r.mu.Lock()
	defer r.mu.Unlock()
	sum := 0
	for i := range r.buckets {
		if e := r.buckets[i].epoch; e <= m && e > m-int64(minutes) {
			sum += r.buckets[i].n
		}
	}
	return sum
}

// Stats is a point-in-time snapshot of tenant load for the operator log / status.
type Stats struct {
	Login, Auth, API, Other uint64 // cumulative requests by surface, since start
	Pushback                uint64 // cumulative 403(HTML)/429/503 across all owners
	LastMinute, Last5Min    int    // rolling request totals
	BreakerOpen             bool   // the fleet circuit is currently paused
	BreakerFor              time.Duration
	// Most recent edge refusal, for the operator status/watchdog. Zero At = none seen.
	LastPushbackAt      time.Time
	LastPushbackSurface string
	LastPushbackStatus  int
	LastPushbackRef     string
	// Breaker-state persistence health: is restart-protection intact? PersistOK is
	// false only if the LAST write failed.
	PersistOK    bool
	PersistError string

	// TruncatedGridAt is the last time a permit list arrived short of the count the
	// tenant reported: the tenant has started paging and we are acting on partial
	// lists until pagination is implemented. Zero means it has never happened.
	TruncatedGridAt   time.Time
	TruncatedGridGot  int
	TruncatedGridWant int

	// Connector success clock, from the real operations the app performs (see
	// health.go): when we last tried the portal, when it last worked, how many
	// operations have failed since, and the coarse derived State the watchdog
	// alerts on. Distinguishes "the scheduler is alive" from "the scheduler's
	// dependency is usable".
	LastAttemptAt       time.Time
	LastSuccessAt       time.Time
	ConsecutiveFailures int
	State               string

	// AuthGated reports the provider's auth-surface circuit: when open, renews and
	// stale-token ops are fast-failing (the council's sign-in is down) while a
	// still-valid cached token keeps serving. AuthGatedFor is the wait until the next
	// recovery probe. Distinct from BreakerOpen, which is the fleet edge breaker.
	// Zero value (not gated) when the provider exposes no auth circuit.
	AuthGated    bool
	AuthGatedFor time.Duration
}

// authGater is the optional provider capability that exposes its auth-surface
// circuit for /status (orikan implements it). Type-asserted, like legacyImporter,
// so a provider without one simply reports not-gated.
type authGater interface {
	AuthGate() (open bool, retry time.Duration)
}

// Blocked reports whether the fleet circuit breaker is currently open — a
// CONFIRMED shared-edge block (several distinct owners refused at once), not one
// owner's isolated cooldown. The scheduler uses it to escalate the user-facing
// warning: when we KNOW the change won't apply, the household should be told to act
// sooner and more firmly than for an ordinary brief hiccup.
func (c *Client) Blocked() bool {
	open, _ := c.breaker.state(time.Now())
	return open
}

// AuthGated reports whether the provider's auth-surface circuit is open — the
// council's sign-in is failing and renews/stale-token ops are being shed. Like
// Blocked (the fleet edge breaker), it is a CONFIRMED "the change won't apply
// until this clears" signal, so the scheduler escalates a stuck permit's warning
// to act-now instead of the reassuring "still updating". False when the provider
// exposes no auth circuit.
func (c *Client) AuthGated() bool {
	open, _ := c.authGate()
	return open
}

// authGate is the single place the provider's optional auth circuit is read (open,
// and the wait until the next probe); AuthGated and Stats both go through it.
func (c *Client) authGate() (open bool, retry time.Duration) {
	if ag, ok := c.p.(authGater); ok {
		return ag.AuthGate()
	}
	return false, 0
}

// LoginBudget is the worst-case time this client's governor may hold a full
// credential login waiting for rate tokens (0 when ungoverned). The scheduler adds
// it to its reconnect deadline so a governed wait can never be what expires it.
func (c *Client) LoginBudget() time.Duration { return c.gov.loginBudget() }

// Stats snapshots current tenant load and breaker state.
func (c *Client) Stats() Stats {
	now := time.Now()
	open, wait := c.breaker.state(now)
	c.traffic.pbMu.Lock()
	pb := c.traffic.lastPB
	c.traffic.pbMu.Unlock()
	c.persistMu.Lock()
	pErr := c.persistErr
	c.persistMu.Unlock()
	c.truncMu.Lock()
	truncAt, truncGot, truncWant := c.truncAt, c.truncGot, c.truncWant
	c.truncMu.Unlock()
	persistError := ""
	if pErr != nil {
		persistError = pErr.Error()
	}
	lastAttempt, lastSuccess, consecFails := c.health.clock()
	authGated, authGatedFor := c.authGate()
	return Stats{
		LastAttemptAt:       lastAttempt,
		LastSuccessAt:       lastSuccess,
		ConsecutiveFailures: consecFails,
		State:               c.health.state(now, open, pb),
		AuthGated:           authGated,
		AuthGatedFor:        authGatedFor,
		Login:               c.traffic.login.Load(),
		Auth:                c.traffic.auth.Load(),
		API:                 c.traffic.api.Load(),
		Other:               c.traffic.other.Load(),
		Pushback:            c.traffic.pushback.Load(),
		LastMinute:          c.traffic.rolling.window(now, 1),
		Last5Min:            c.traffic.rolling.window(now, 5),
		BreakerOpen:         open,
		BreakerFor:          wait,
		LastPushbackAt:      pb.At,
		LastPushbackSurface: pb.Surface,
		LastPushbackStatus:  pb.Status,
		LastPushbackRef:     pb.AzureRef,
		PersistOK:           pErr == nil,
		PersistError:        persistError,
		TruncatedGridAt:     truncAt,
		TruncatedGridGot:    truncGot,
		TruncatedGridWant:   truncWant,
	}
}
