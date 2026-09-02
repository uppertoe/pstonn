package orikan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// TestRecordAuthorizeOutcomeClassification pins how each authorize result is routed:
// only a plain origin 5xx (or a transport failure) is "upstream down". Edge push-back
// (a typed *provider.Unavailable, which includes 503) belongs to the fleet breaker, and
// our own cancellation is not an upstream signal — neither may open the auth circuit.
func TestRecordAuthorizeOutcomeClassification(t *testing.T) {
	openAfter := func(status int, err error) bool {
		c := &Client{authCircuit: &authCircuit{}}
		for i := 0; i < authTripThreshold+2; i++ {
			c.recordAuthorizeOutcome(false, status, err)
		}
		open, _ := c.authCircuit.state(time.Now())
		return open
	}
	if openAfter(503, &provider.Unavailable{Status: 503}) {
		t.Error("a 503 edge push-back (fleet breaker's job) must not open the auth circuit")
	}
	if openAfter(0, fmt.Errorf("get: %w", context.Canceled)) {
		t.Error("our own cancellation must not open the auth circuit")
	}
	if !openAfter(500, fmt.Errorf("authorize: http 500")) {
		t.Error("a sustained origin 500 should open the auth circuit")
	}
	if !openAfter(0, fmt.Errorf("dial tcp: connection refused")) {
		t.Error("a sustained transport failure should open the auth circuit")
	}
}

// TestAuthorizeCircuitTripsOn5xxAndFastFails: a sustained council auth 500 trips the
// circuit after the threshold, and further authorizes then fast-fail WITHOUT touching
// the council — and the fast-fail is not a *provider.Unavailable, so the fleet breaker
// (which would pause valid-token API ops too) is never engaged.
func TestAuthorizeCircuitTripsOn5xxAndFastFails(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError) // council IdentityServer 500
	}))
	defer srv.Close()
	c := New(Config{Issuer: srv.URL + "/idm", APIBase: srv.URL + "/ssp-svc", ClientID: "t", RedirectURI: srv.URL + "/ssp/callback"}, nil)

	for i := 0; i < authTripThreshold; i++ {
		if _, _, _, err := c.authorizeWithCookie(context.Background(), "c=1"); err == nil {
			t.Fatalf("attempt %d: expected the 500 to error", i)
		}
	}
	if got := atomic.LoadInt32(&hits); got != authTripThreshold {
		t.Fatalf("expected %d council hits before the circuit opened, got %d", authTripThreshold, got)
	}

	// Circuit open: the next authorize fast-fails without a council hit.
	_, _, _, err := c.authorizeWithCookie(context.Background(), "c=1")
	if !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("open circuit should fast-fail as unavailable (busy); got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != authTripThreshold {
		t.Fatalf("open circuit still hit the council: %d hits, want %d", got, authTripThreshold)
	}
	var u *provider.Unavailable
	if errors.As(err, &u) {
		t.Fatal("the auth backoff must not be a *provider.Unavailable — that would feed the fleet breaker")
	}
}

func TestAuthCircuitOpensAfterThresholdAndProbes(t *testing.T) {
	a := &authCircuit{}
	now := time.Now()

	// Closed: every authorize is allowed, none is a probe.
	for i := 0; i < authTripThreshold-1; i++ {
		probe, ok, _ := a.allow(now)
		if probe || !ok {
			t.Fatalf("closed circuit should allow (not probe); got probe=%v ok=%v", probe, ok)
		}
		a.onUpstreamFailure(now, false) // a closed-admitted authorize hit a 5xx
	}
	// Still closed one failure short of the threshold.
	if _, ok, _ := a.allow(now); !ok {
		t.Fatal("circuit opened before the threshold")
	}
	a.onUpstreamFailure(now, false) // the threshold-th failure

	// Now open: further authorizes are blocked (no council hit) until the base wait.
	if _, ok, retry := a.allow(now); ok || retry <= 0 {
		t.Fatalf("open circuit should block with a positive retry; ok=%v retry=%v", ok, retry)
	}
	if _, ok, _ := a.allow(now.Add(authProbeBase - time.Second)); ok {
		t.Fatal("circuit admitted before the base backoff elapsed")
	}

	// Past the base wait it admits exactly ONE probe; a concurrent attempt is blocked.
	probe, ok, _ := a.allow(now.Add(authProbeBase))
	if !probe || !ok {
		t.Fatalf("expected the probe to be admitted; probe=%v ok=%v", probe, ok)
	}
	if _, ok, _ := a.allow(now.Add(authProbeBase)); ok {
		t.Fatal("a second request slipped past while the probe was in flight")
	}

	// The probe fails → the wait DOUBLES and no probe is admitted until then.
	t2 := now.Add(authProbeBase)
	a.onUpstreamFailure(t2, true)
	if _, ok, _ := a.allow(t2.Add(authProbeBase*2 - time.Second)); ok {
		t.Fatal("escalated backoff not respected after a failed probe")
	}
	if _, ok, _ := a.allow(t2.Add(authProbeBase * 2)); !ok {
		t.Fatal("next probe not admitted after the doubled wait")
	}
}

// TestAuthCircuitInconclusiveIsNeutralNotResetting pins the streak contract: an
// inconclusive result (edge push-back / odd redirect) is neutral — it does not advance
// the count toward opening AND does not reset it — whereas a success does reset. So an
// edge 503 interleaved with genuine origin 500s must not keep us hammering a down origin.
func TestAuthCircuitInconclusiveIsNeutralNotResetting(t *testing.T) {
	now := time.Now()

	a := &authCircuit{}
	a.onUpstreamFailure(now, false) // fails=1
	a.onUpstreamFailure(now, false) // fails=2
	a.onInconclusive(now, false)    // neutral: neither counts nor resets
	if open, _ := a.state(now); open {
		t.Fatal("two failures + an inconclusive should not open yet")
	}
	a.onUpstreamFailure(now, false) // the third upstream failure -> open
	if open, _ := a.state(now); !open {
		t.Fatal("an inconclusive between failures must be neutral, not reset the streak")
	}

	// A success, by contrast, resets the streak.
	b := &authCircuit{}
	b.onUpstreamFailure(now, false)
	b.onUpstreamFailure(now, false)
	b.onSuccess(false) // proof the IdP served -> reset
	b.onUpstreamFailure(now, false)
	b.onUpstreamFailure(now, false)
	if open, _ := b.state(now); open {
		t.Fatal("a success must reset the streak; two more failures should not reopen")
	}
}

func TestAuthCircuitProbeSuccessCloses(t *testing.T) {
	a := &authCircuit{}
	now := time.Now()
	for i := 0; i < authTripThreshold; i++ {
		a.onUpstreamFailure(now, false)
	}
	probe, ok, _ := a.allow(now.Add(authProbeBase))
	if !probe || !ok {
		t.Fatal("probe should be admitted")
	}
	a.onSuccess(true) // the probe reached a serving upstream
	if open, _ := a.state(now); open {
		t.Fatal("a successful probe must close the circuit")
	}
	if p, ok, _ := a.allow(now); p || !ok {
		t.Fatalf("closed circuit should allow non-probe traffic; probe=%v ok=%v", p, ok)
	}
}

func TestAuthCircuitBackoffCaps(t *testing.T) {
	a := &authCircuit{}
	now := time.Now()
	for i := 0; i < authTripThreshold; i++ {
		a.onUpstreamFailure(now, false)
	}
	// Fail many probes; the wait must never exceed authProbeMax.
	at := now
	for i := 0; i < 10; i++ {
		at = at.Add(a.backoff)
		if _, ok, _ := a.allow(at); !ok {
			t.Fatalf("probe %d not admitted at its due time", i)
		}
		a.onUpstreamFailure(at, true)
	}
	if a.backoff > authProbeMax {
		t.Fatalf("backoff %s exceeded the cap %s", a.backoff, authProbeMax)
	}
	if a.backoff != authProbeMax {
		t.Fatalf("backoff should have climbed to the cap; got %s", a.backoff)
	}
}

func TestAuthCircuitInconclusiveDoesNotOpenOrClose(t *testing.T) {
	a := &authCircuit{}
	now := time.Now()
	// Edge push-back while closed must not open the circuit.
	a.onInconclusive(now, false)
	a.onInconclusive(now, false)
	a.onInconclusive(now, false)
	if open, _ := a.state(now); open {
		t.Fatal("inconclusive results must not open the auth circuit (that is the fleet breaker's job)")
	}
	// While open, an inconclusive probe re-arms the SAME wait (no escalation, no close).
	for i := 0; i < authTripThreshold; i++ {
		a.onUpstreamFailure(now, false)
	}
	before := a.backoff
	probe, ok, _ := a.allow(now.Add(authProbeBase))
	if !probe || !ok {
		t.Fatal("probe should be admitted")
	}
	a.onInconclusive(now.Add(authProbeBase), true)
	if a.backoff != before {
		t.Fatalf("inconclusive probe changed the backoff: %s -> %s", before, a.backoff)
	}
	if open, _ := a.state(now); !open {
		t.Fatal("inconclusive probe must not close the circuit")
	}
}
