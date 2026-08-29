package orikan

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
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

	client := &http.Client{Transport: identityTransport{base: http.DefaultTransport}}
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
func TestTenantIdentityDefaultsHonest(t *testing.T) {
	for path, wantBrowser := range map[string]bool{
		"/idm/Account/Login":                 true,
		"/connect/token":                     true,
		"/connect/authorize":                 true,
		"/ssp-svc/api/Index/grid":            false,
		"/ssp-svc/api/permits/manageVehicle": false,
		"/something/unexpected":              false,
		"/":                                  false,
	} {
		s := surfaceOfPath(path)
		if got := s == provider.SurfaceLogin || s == provider.SurfaceAuth; got != wantBrowser {
			t.Errorf("surfaceOfPath(%q) = %v (browser=%v), want browser=%v", path, s, got, wantBrowser)
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

func TestSurfaceOfPath(t *testing.T) {
	cases := []struct {
		path string
		want provider.Surface
	}{
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
		if got := surfaceOfPath(c.path); got != c.want {
			t.Errorf("surfaceOfPath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
