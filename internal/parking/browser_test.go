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

// TestBrowserTransportIdentityBySurface pins the split identity: the OIDC login
// flow presents the SPA's Chrome identity (with matching client hints), the permit
// API identifies honestly as p.stonn with NO Chrome client hints, and neither ever
// ships Go's default UA.
func TestBrowserTransportIdentityBySurface(t *testing.T) {
	var gotUA, gotChUA, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotChUA = r.Header.Get("sec-ch-ua")
		gotAccept = r.Header.Get("Accept")
	}))
	defer srv.Close()

	client := &http.Client{Transport: browserTransport{base: http.DefaultTransport}}
	get := func(path string) {
		t.Helper()
		gotUA, gotChUA, gotAccept = "", "", ""
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		if _, err := client.Do(req); err != nil {
			t.Fatal(err)
		}
	}

	// The OIDC login surface: the SPA's Chrome identity, coherent with its hints.
	get("/connect/authorize")
	if !strings.Contains(gotUA, "Chrome/") {
		t.Fatalf("login-surface UA = %q, want the Chrome identity", gotUA)
	}
	if gotChUA == "" {
		t.Fatal("login-surface sec-ch-ua was not set")
	}

	// The permit API surface: honest p.stonn, and crucially NO Chrome client hints
	// — a p.stonn UA carrying Chrome hints would be the exact incoherence the split
	// removes.
	get("/ssp-svc/api/Index/grid")
	if !strings.Contains(gotUA, "p.stonn/") {
		t.Fatalf("api-surface UA = %q, want the honest p.stonn identity", gotUA)
	}
	if strings.Contains(gotUA, "Chrome/") {
		t.Fatalf("api-surface UA still claims to be Chrome: %q", gotUA)
	}
	if gotChUA != "" {
		t.Fatalf("api-surface leaked Chrome client hints: sec-ch-ua = %q", gotChUA)
	}

	// Neither surface may ever emit Go's default UA.
	for _, p := range []string{"/connect/authorize", "/ssp-svc/api/x", "/Account/Login", "/anything"} {
		get(p)
		if strings.Contains(gotUA, "Go-http-client") || gotUA == "" {
			t.Fatalf("path %s shipped a bare/Go UA: %q", p, gotUA)
		}
	}

	// Caller-set header must survive on either surface.
	req, _ := http.NewRequest("GET", srv.URL+"/ssp-svc/api/x", nil)
	req.Header.Set("Accept", "application/json")
	if _, err := client.Do(req); err != nil {
		t.Fatal(err)
	}
	if gotAccept != "application/json" {
		t.Fatalf("caller Accept overwritten: got %q", gotAccept)
	}
}

// An unrecognised path must default to the honest identity, never the browser
// costume: the disguise is granted only to paths positively identified as the
// SPA's own login flow.
func TestCouncilIdentityDefaultsHonest(t *testing.T) {
	for path, wantBrowser := range map[string]bool{
		"/idm/Account/Login":                 true,
		"/connect/token":                     true,
		"/connect/authorize":                 true,
		"/ssp-svc/api/Index/grid":            false,
		"/ssp-svc/api/permits/manageVehicle": false,
		"/something/unexpected":              false,
		"/":                                  false,
	} {
		if got := councilIdentityBrowser(path); got != wantBrowser {
			t.Errorf("councilIdentityBrowser(%q) = %v, want %v", path, got, wantBrowser)
		}
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
	const owner = "o@example.com"
	key := regKey{owner, p.CouncilPermitID}

	// Nothing cached yet: a miss, not a blocking fetch.
	if _, _, fresh, err := c.CurrentVehicleCached(ctx, owner, p, 5*time.Minute); !errors.Is(err, ErrNoCachedPlate) || fresh {
		t.Fatalf("empty cache: want ErrNoCachedPlate and not fresh, got fresh=%v, %v", fresh, err)
	}

	// Fresh cache is served and reported fresh.
	c.regCache.Store(key, cachedReg{reg: "ABC123", at: time.Now()})
	if got, _, fresh, err := c.CurrentVehicleCached(ctx, owner, p, 5*time.Minute); err != nil || got != "ABC123" || !fresh {
		t.Fatalf("fresh cache: got %q fresh=%v, %v", got, fresh, err)
	}

	// A stale value is still served (revalidation happens in the background),
	// reported non-fresh so the UI can offer a follow-up fetch.
	c.regCache.Store(key, cachedReg{reg: "ABC123", at: time.Now().Add(-time.Hour)})
	if got, age, fresh, err := c.CurrentVehicleCached(ctx, owner, p, 5*time.Minute); err != nil || got != "ABC123" || fresh || age < time.Hour {
		t.Fatalf("stale cache: got %q fresh=%v age=%v, %v", got, fresh, age, err)
	}
}

// C9: a council permit can change hands — a household permit is visible to two
// council logins, and "stop managing" plus "manage" from the other account is the
// ordinary way that happens. A plate cached under the previous holder must never
// be served to the new one, and stopping must clear the entry.
func TestRegCacheIsOwnerScopedAndForgettable(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := &Client{store: st} // unlinked: a background refresh cannot supply an answer
	ctx := context.Background()
	p := model.Permit{CouncilPermitID: "14576"}
	const first, second = "first@example.com", "second@example.com"

	c.regCache.Store(regKey{first, p.CouncilPermitID}, cachedReg{reg: "OLD111", at: time.Now()})

	// The new holder of the same council permit gets a cache MISS, not the previous
	// household's plate.
	if got, _, fresh, err := c.CurrentVehicleCached(ctx, second, p, 5*time.Minute); !errors.Is(err, ErrNoCachedPlate) || got != "" || fresh {
		t.Fatalf("second owner read the first owner's cached plate: %q fresh=%v, %v", got, fresh, err)
	}
	// The original owner still sees their own.
	if got, _, _, err := c.CurrentVehicleCached(ctx, first, p, 5*time.Minute); err != nil || got != "OLD111" {
		t.Fatalf("first owner lost their own entry: %q, %v", got, err)
	}

	// Stopping management drops it, and only theirs.
	c.regCache.Store(regKey{second, p.CouncilPermitID}, cachedReg{reg: "NEW222", at: time.Now()})
	c.ForgetPermit(first, p.CouncilPermitID)
	if _, _, _, err := c.CurrentVehicleCached(ctx, first, p, 5*time.Minute); !errors.Is(err, ErrNoCachedPlate) {
		t.Fatalf("ForgetPermit left the entry behind: %v", err)
	}
	if got, _, _, err := c.CurrentVehicleCached(ctx, second, p, 5*time.Minute); err != nil || got != "NEW222" {
		t.Fatalf("ForgetPermit evicted another owner's entry: %q, %v", got, err)
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
