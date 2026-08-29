package parking

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/provider"
)

// Transport is the single chokepoint every outbound request to one portal passes
// through: it governs rate and concurrency (governor.go) and counts traffic by
// surface, using the surface the provider tagged on the request context. A
// provider is built ON this transport, so its identity headers sit above it and
// its requests are counted below.
type Transport struct {
	base    http.RoundTripper
	gov     *governor
	traffic *trafficCounters
}

// Limits are the transport's ceilings. Zero values take the built-in defaults.
type Limits struct {
	RatePerMin      int // global ceiling across every request to this portal
	Burst           int
	LoginRatePerMin int // sub-limit for the credential-login surface
	LoginBurst      int
	Concurrency     int // max simultaneous requests
}

// LimitsFromConfig reads the COUNCIL_GOV_* settings.
func LimitsFromConfig(c config.CouncilConfig) Limits {
	return Limits{RatePerMin: c.GovRatePerMin, Burst: c.GovBurst,
		LoginRatePerMin: c.GovLoginRatePerMin, LoginBurst: c.GovLoginBurst, Concurrency: c.GovConcurrency}
}

// NewTransport builds a governed, counted transport over http.DefaultTransport.
func NewTransport(l Limits) *Transport {
	return &Transport{
		base: http.DefaultTransport,
		gov: newGovernor(
			govOr(l.RatePerMin, defaultGovTotalPerMin),
			govOr(l.Burst, defaultGovTotalBurst),
			govOr(l.LoginRatePerMin, defaultGovLoginPerMin),
			govOr(l.LoginBurst, defaultGovLoginBurst),
			govIntOr(l.Concurrency, defaultGovConcurrency)),
		traffic: newTrafficCounters(),
	}
}

// RoundTrip governs, counts, then sends.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	surface := provider.SurfaceOf(req.Context())
	release, err := t.gov.acquire(req.Context(), surface)
	if err != nil {
		return nil, err
	}
	defer release()
	t.traffic.count(surface)
	return t.base.RoundTrip(req)
}

type trafficCounters struct {
	login, auth, api, other atomic.Uint64
	pushback                atomic.Uint64   // 403(HTML)/429/503 across all owners
	rolling                 *rollingCounter // request-rate windows; nil-safe (tests)
	pbMu                    sync.Mutex
	lastPB                  PushbackEvent // most recent pushback, for /status + operator log
}

func newTrafficCounters() *trafficCounters {
	// Track request rate with headroom over the widest window Stats queries (5m):
	// the extra slots keep each in-window minute in its own bucket even if adds
	// ever arrive slightly out of order.
	return &trafficCounters{rolling: newRollingCounter(8)}
}

func (t *trafficCounters) count(surface provider.Surface) {
	switch surface {
	case provider.SurfaceLogin:
		t.login.Add(1)
	case provider.SurfaceAuth:
		t.auth.Add(1)
	case provider.SurfaceAPI:
		t.api.Add(1)
	default:
		t.other.Add(1)
	}
	t.rolling.add(time.Now())
}
