package parking

import (
	"log"
	"net/http"
	"sync"
	"time"
)

// PushbackEvent is a privacy-safe diagnostic snapshot of the last time the council
// edge refused us (a 403 HTML challenge, 429, or 503). If we are ever blocked, this
// is what tells us WHICH control fired — a rate limit, a bot rule, a managed WAF
// rule, or platform throttling — since the client cannot see the edge's config.
// The X-Azure-Ref correlation id is the single most useful field: it is what the
// council (or Microsoft) would look the incident up by.
type PushbackEvent struct {
	At          time.Time
	Surface     string // login / auth / api
	Status      int
	ContentType string
	RetryAfter  time.Duration
	AzureRef    string // X-Azure-Ref: the Azure Front Door correlation id
}

// recordPushback captures the diagnostic fields of an edge refusal and logs them,
// so a block leaves a trail the operator can act on. Called at every pushback site.
func (c *Client) recordPushback(resp *http.Response) {
	surface := "other"
	if resp.Request != nil && resp.Request.URL != nil {
		surface = classifyCouncilPath(resp.Request.URL.Path)
	}
	ev := PushbackEvent{
		At:          time.Now(),
		Surface:     surface,
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		RetryAfter:  parseRetryAfter(resp),
		AzureRef:    resp.Header.Get("X-Azure-Ref"),
	}
	c.traffic.pbMu.Lock()
	c.traffic.lastPB = ev
	c.traffic.pbMu.Unlock()
	log.Printf("parking: council pushback %s %d (content-type=%q retry-after=%s x-azure-ref=%q)",
		surface, ev.Status, safeExcerpt(ev.ContentType), ev.RetryAfter.Round(time.Second), safeExcerpt(ev.AzureRef))
}

// The cumulative per-surface counters answer "how much have we ever asked of the
// council". They cannot answer the question that matters at fleet scale: "how hard
// are we hitting the edge RIGHT NOW". The scheduler spaces permit OPERATIONS, but
// each operation is several HTTP requests (token renew, read, write, confirm), so
// the instantaneous request rate is a multiple of the operation rate and bursts
// around a rollover. rollingCounter measures the real thing — requests in the last
// minute and five minutes — so the operator (and any future dashboard) sees actual
// load, not an inferred one, and can tell whether we are near a rate that would
// draw push-back.
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

// Stats is a point-in-time snapshot of council load for the operator log / status.
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
	// council reported: the council has started paging and we are acting on partial
	// lists until pagination is implemented. Zero means it has never happened.
	TruncatedGridAt   time.Time
	TruncatedGridGot  int
	TruncatedGridWant int
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

// Stats snapshots current council load and breaker state.
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
	return Stats{
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
