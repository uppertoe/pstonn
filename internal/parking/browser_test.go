package parking

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/store"
)

// TestBrowserTransportSetsUA confirms every outbound request carries a browser
// User-Agent (never Go's default) and the client-hint headers, and that an
// explicitly-set header is not overwritten.
func TestBrowserTransportSetsUA(t *testing.T) {
	var gotUA, gotChUA, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotChUA = r.Header.Get("sec-ch-ua")
		gotAccept = r.Header.Get("Accept")
	}))
	defer srv.Close()

	client := &http.Client{Transport: browserTransport{base: http.DefaultTransport}}

	// No headers set: transport must supply them.
	if _, err := client.Get(srv.URL); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotUA, "Go-http-client") || !strings.Contains(gotUA, "Chrome/") {
		t.Fatalf("User-Agent = %q, want a Chrome UA and never the Go default", gotUA)
	}
	if gotChUA == "" {
		t.Fatal("sec-ch-ua header was not set")
	}

	// Caller-set header must survive.
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept", "application/json")
	if _, err := client.Do(req); err != nil {
		t.Fatal(err)
	}
	if gotAccept != "application/json" {
		t.Fatalf("caller Accept overwritten: got %q", gotAccept)
	}
}

func TestParseRetryAfter(t *testing.T) {
	mk := func(v string) *http.Response {
		h := http.Header{}
		if v != "" {
			h.Set("Retry-After", v)
		}
		return &http.Response{Header: h}
	}
	if d := parseRetryAfter(mk("120")); d != 120*time.Second {
		t.Fatalf("delta-seconds: got %v, want 120s", d)
	}
	if d := parseRetryAfter(mk("")); d != 0 {
		t.Fatalf("absent header: got %v, want 0", d)
	}
	if d := parseRetryAfter(mk("garbage")); d != 0 {
		t.Fatalf("garbage: got %v, want 0", d)
	}
}

func TestClassifyCouncilPath(t *testing.T) {
	cases := []struct{ path, want string }{
		{"/idm/Account/Login", "login"},
		{"/idm", "login"}, // the credential POST goes to /idm?returnurl=…
		{"/idm/", "login"},
		{"/idm/connect/authorize", "auth"},
		{"/idm/connect/authorize/callback", "auth"},
		{"/idm/connect/token", "auth"},
		{"/ssp-svc/api/Index/grid", "api"},
		{"/ssp-svc/api/permits/manageVehicle", "api"},
		{"/ssp/callback", "other"},
	}
	for _, c := range cases {
		if got := classifyCouncilPath(c.path); got != c.want {
			t.Errorf("classifyCouncilPath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// TestCurrentVehicleCachedNeverBlocks locks in the stale-while-revalidate
// contract: the call must answer from cache (fresh or stale) or report a miss —
// never a synchronous council round trip, which would let a slow portal stall a
// page render past the HTTP server's WriteTimeout (a 502 at the proxy).
func TestCurrentVehicleCachedNeverBlocks(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := &Client{store: st} // no session stored: any background refresh fails fast
	ctx := context.Background()
	p := model.Permit{CouncilPermitID: "14576"}

	// Nothing cached yet: a miss, not a blocking fetch.
	if _, fresh, err := c.CurrentVehicleCached(ctx, "o@example.com", p, 5*time.Minute); !errors.Is(err, ErrNoCachedPlate) || fresh {
		t.Fatalf("empty cache: want ErrNoCachedPlate and not fresh, got fresh=%v, %v", fresh, err)
	}

	// Fresh cache is served and reported fresh.
	c.regCache.Store("14576", cachedReg{reg: "ABC123", at: time.Now()})
	if got, fresh, err := c.CurrentVehicleCached(ctx, "o@example.com", p, 5*time.Minute); err != nil || got != "ABC123" || !fresh {
		t.Fatalf("fresh cache: got %q fresh=%v, %v", got, fresh, err)
	}

	// A stale value is still served (revalidation happens in the background),
	// reported non-fresh so the UI can offer a follow-up fetch.
	c.regCache.Store("14576", cachedReg{reg: "ABC123", at: time.Now().Add(-time.Hour)})
	if got, fresh, err := c.CurrentVehicleCached(ctx, "o@example.com", p, 5*time.Minute); err != nil || got != "ABC123" || fresh {
		t.Fatalf("stale cache: got %q fresh=%v, %v", got, fresh, err)
	}
}

// TestCooldownBackoff confirms a penalised owner enters cooldown and that a
// success clears it.
func TestCooldownBackoff(t *testing.T) {
	c := &Client{}
	const owner = "a@b.com"
	if _, blocked := c.cooldownFor(owner); blocked {
		t.Fatal("owner should start un-penalised")
	}
	c.penalize(owner, 0)
	if _, blocked := c.cooldownFor(owner); !blocked {
		t.Fatal("owner should be in cooldown after a penalty")
	}
	c.clearPenalty(owner)
	if _, blocked := c.cooldownFor(owner); blocked {
		t.Fatal("cooldown should clear after success")
	}
}
