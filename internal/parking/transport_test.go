package parking

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Two councils' transports sharing one ConcurrencyLimit never put more than its
// slots on the wire at once, however generous their own governors are.
func TestSharedConcurrencyLimitSpansTransports(t *testing.T) {
	var inflight, peak atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inflight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		inflight.Add(-1)
	}))
	defer srv.Close()

	shared := NewConcurrencyLimit(2)
	wide := Limits{RatePerMin: 1 << 20, Burst: 1 << 20, LoginRatePerMin: 1 << 20, LoginBurst: 1 << 20, Concurrency: 8}
	a := &http.Client{Transport: NewTransport(wide).Share(shared)}
	b := &http.Client{Transport: NewTransport(wide).Share(shared)}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		c := a
		if i%2 == 1 {
			c = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
			resp, err := c.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > 2 {
		t.Fatalf("peak concurrency across the two transports = %d, want ≤ 2", p)
	}
	// A waiter gives up with its context rather than hanging on a full limit.
	shared.slots <- struct{}{}
	shared.slots <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if _, err := a.Do(req); err == nil {
		t.Fatal("a request on a full shared limit must fail with its context, not hang")
	}
}

// A waiter on a full shared limit gives up with its context and leaves no slot
// consumed; a limit of zero takes the default.
func TestSharedLimitCancellationLeavesNoSlot(t *testing.T) {
	l := NewConcurrencyLimit(0)
	if cap(l.slots) != defaultGovConcurrency {
		t.Fatalf("zero limit = %d, want the default %d", cap(l.slots), defaultGovConcurrency)
	}
	l = NewConcurrencyLimit(1)
	l.slots <- struct{}{}
	tr := NewTransport(Limits{}).Share(l)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:1/", nil)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("cancelled waiter must fail")
	}
	if len(l.slots) != 1 {
		t.Fatalf("slot count changed to %d after a cancelled wait", len(l.slots))
	}
}
