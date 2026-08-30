package orikan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// confirmFixture is a portal that accepts the manageVehicle POST with a 2xx and
// answers the managedVehicle reads from a script: reads[i] is what the i-th GET
// shows, the last entry repeating thereafter.
func confirmFixture(t *testing.T, reads []string) (*Client, *provider.Session, *atomic.Int32, *httptest.Server) {
	t.Helper()
	var gets, posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/ssp-svc/api/permits/managedVehicle":
			i := int(gets.Add(1)) - 1
			if i >= len(reads) {
				i = len(reads) - 1
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"permitNumber":"VPP-1","permitVehicleCount":1,"maxVehicles":1,"canAddVehicle":false,"canEditOrDeleteVehicle":true,`+
				`"permitVehicles":[{"PKPermitVehicleDetailID":42,"RegistrationNumber":%q,"FKVehicleStateID":"1"}]}`, reads[i])
		case r.Method == http.MethodPost && r.URL.Path == "/ssp-svc/api/permits/manageVehicle":
			posts.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	c := New(Config{Issuer: srv.URL + "/idm", APIBase: srv.URL + "/ssp-svc", ClientID: "t", RedirectURI: srv.URL + "/ssp/callback"}, nil)
	b, err := json.Marshal(session{Cookie: "c=1", AccessToken: "tok", TokenExpiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	s := provider.Session(b)
	return c, &s, &gets, srv
}

func shortConfirmDelay(t *testing.T) {
	t.Helper()
	prev := confirmRetryDelay
	confirmRetryDelay = 5 * time.Millisecond
	t.Cleanup(func() { confirmRetryDelay = prev })
}

// A stale first read-back after a 2xx is lag, not refusal: one re-read that
// agrees is success.
func TestConfirmWriteRetriesOneStaleRead(t *testing.T) {
	shortConfirmDelay(t)
	c, s, gets, _ := confirmFixture(t, []string{"OLD111", "OLD111", "NEW222"})
	err := c.SetVehicle(context.Background(), s, provider.PermitRef{ID: "7"}, provider.Vehicle{Registration: "NEW222"})
	if err != nil {
		t.Fatalf("a stale-then-settled read-back should succeed, got %v", err)
	}
	// pre-write read + first confirm + one retry: exactly one extra request.
	if n := gets.Load(); n != 3 {
		t.Fatalf("expected 3 reads (pre, confirm, retry), got %d", n)
	}
}

// Two reads that both still show the old plate are a durable refusal.
func TestConfirmWriteRejectsPersistentMismatch(t *testing.T) {
	shortConfirmDelay(t)
	c, s, gets, _ := confirmFixture(t, []string{"OLD111"})
	err := c.SetVehicle(context.Background(), s, provider.PermitRef{ID: "7"}, provider.Vehicle{Registration: "NEW222"})
	if err == nil {
		t.Fatal("a persistent mismatch must not be reported as success")
	}
	if kind, op := provider.FailureOf(err); kind != provider.FailRejected || op != provider.OpSetVehicle {
		t.Fatalf("classified %v/%v, want FailRejected/%v", kind, op, provider.OpSetVehicle)
	}
	if n := gets.Load(); n != 3 {
		t.Fatalf("expected exactly 3 reads (no unbounded polling), got %d", n)
	}
}

// A read-back that agrees first time costs no extra request.
func TestConfirmWriteImmediateMatchNoRetry(t *testing.T) {
	shortConfirmDelay(t)
	c, s, gets, _ := confirmFixture(t, []string{"OLD111", "NEW222"})
	if err := c.SetVehicle(context.Background(), s, provider.PermitRef{ID: "7"}, provider.Vehicle{Registration: "NEW222"}); err != nil {
		t.Fatal(err)
	}
	if n := gets.Load(); n != 2 {
		t.Fatalf("expected 2 reads (pre, confirm), got %d", n)
	}
}

// A context that ends during the retry pause yields transient, never a
// durable refusal the user would be told to act on.
func TestConfirmWriteCancelledDuringRetryIsTransient(t *testing.T) {
	prev := confirmRetryDelay
	confirmRetryDelay = time.Hour
	t.Cleanup(func() { confirmRetryDelay = prev })
	c, s, gets, _ := confirmFixture(t, []string{"OLD111"})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for gets.Load() < 2 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	err := c.SetVehicle(ctx, s, provider.PermitRef{ID: "7"}, provider.Vehicle{Registration: "NEW222"})
	if kind, _ := provider.FailureOf(err); err == nil || kind != provider.FailTransient {
		t.Fatalf("got %v (kind %v), want a transient failure", err, kind)
	}
}
