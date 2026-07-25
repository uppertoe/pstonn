package parking

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// fakeCouncil is an httptest server standing in for both the IDM and the permit
// API, so the request/renew classification logic runs offline.
type fakeCouncil struct {
	srv *httptest.Server
	mux *http.ServeMux

	renews  atomic.Int64 // completed silent-renew authorize calls
	apiCode atomic.Int64 // status the API endpoint returns; 0 = 200 JSON
	apiCT   atomic.Value // Content-Type for non-2xx API responses
}

func newFakeCouncil(t *testing.T) *fakeCouncil {
	t.Helper()
	f := &fakeCouncil{mux: http.NewServeMux()}
	f.apiCT.Store("text/html")
	f.mux.HandleFunc("/idm/connect/authorize", func(w http.ResponseWriter, r *http.Request) {
		f.renews.Add(1)
		cb := r.URL.Query().Get("redirect_uri")
		http.Redirect(w, r, cb+"?code=fresh-code&state="+r.URL.Query().Get("state"), http.StatusFound)
	})
	f.mux.HandleFunc("/idm/connect/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "fresh-token", "expires_in": 3600, "token_type": "Bearer"})
	})
	f.mux.HandleFunc("/ssp-svc/api/permits/managedVehicle", func(w http.ResponseWriter, r *http.Request) {
		if code := int(f.apiCode.Load()); code != 0 {
			// Reject stale tokens but accept a renewed one, unless a fixed
			// status is forced.
			if code == http.StatusUnauthorized && r.Header.Get("Authorization") == "Bearer fresh-token" {
				// fall through to success
			} else {
				w.Header().Set("Content-Type", f.apiCT.Load().(string))
				w.WriteHeader(code)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"permitNumber": "VPP1", "permitVehicleCount": 1, "maxVehicles": 1,
			"canAddVehicle": false, "canEditOrDeleteVehicle": true,
			"permitVehicles": []map[string]any{{"PKPermitVehicleDetailID": 1, "RegistrationNumber": "AAA111", "FKVehicleStateID": "1"}},
		})
	})
	f.srv = httptest.NewServer(f.mux)
	t.Cleanup(f.srv.Close)
	return f
}

// testClient wires a Client at the fake council with a real store + box and a
// linked owner whose cached access token is "stale-token" (unexpired).
func testClient(t *testing.T, f *fakeCouncil) (*Client, *store.Store, *secretbox.Box) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, err := secretbox.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	base := f.srv.URL
	c := &Client{
		clientID:    "test-client",
		redirectURI: base + "/ssp/callback",
		scope:       "openid",
		authURL:     base + "/idm/connect/authorize",
		tokenURL:    base + "/idm/connect/token",
		loginURL:    base + "/idm/Account/Login",
		apiBase:     base + "/ssp-svc",
		origin:      base,
		store:       st,
		box:         box,
		http: &http.Client{
			Timeout:       10 * time.Second,
			Transport:     browserTransport{base: http.DefaultTransport},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	return c, st, box
}

func linkOwner(t *testing.T, c *Client, st *store.Store, box *secretbox.Box, owner string) {
	t.Helper()
	ctx := context.Background()
	sealedCookie, err := box.Seal("Permits.IDM.Identity=abc")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCouncilSession(ctx, store.CouncilSession{Owner: owner, Cookie: sealedCookie}); err != nil {
		t.Fatal(err)
	}
	sealedAT, err := box.Seal("stale-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateCouncilToken(ctx, owner, sealedCookie, sealedAT, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// A 401 on a cached-but-kicked token must trigger one silent renew and a retry,
// not surface a FailRejected "act now" alarm while the dead token stays cached.
func TestAPIRequest401RenewsAndRetries(t *testing.T) {
	f := newFakeCouncil(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, "kicked@example.com")
	f.apiCode.Store(http.StatusUnauthorized)

	resp, err := c.apiRequest(context.Background(), "kicked@example.com", http.MethodGet,
		"/api/permits/managedVehicle", "read", url.Values{"permitID": {"1"}}, nil)
	if err != nil {
		t.Fatalf("expected renew+retry to succeed, got %v", err)
	}
	drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after renew", resp.StatusCode)
	}
	if f.renews.Load() != 1 {
		t.Fatalf("silent renews = %d, want exactly 1", f.renews.Load())
	}
}

// An HTML 403 is Akamai push-back: transient, penalized, ErrCouncilBusy.
func TestAPIRequest403HTMLIsBusy(t *testing.T) {
	f := newFakeCouncil(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, "blocked@example.com")
	f.apiCode.Store(http.StatusForbidden)
	f.apiCT.Store("text/html")

	_, err := c.apiRequest(context.Background(), "blocked@example.com", http.MethodGet,
		"/api/permits/managedVehicle", "read", nil, nil)
	if !errors.Is(err, ErrCouncilBusy) {
		t.Fatalf("err = %v, want ErrCouncilBusy", err)
	}
	if _, blocked := c.cooldownFor("blocked@example.com"); !blocked {
		t.Fatal("an HTML 403 must start a cooldown")
	}
}

// A JSON 403 is the API itself refusing (e.g. permit access revoked): durable,
// FailRejected, and NO cooldown — otherwise a permanent condition is retried
// forever under a soothing "temporarily unavailable" label.
func TestAPIRequest403JSONIsRejected(t *testing.T) {
	f := newFakeCouncil(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, "revoked@example.com")
	f.apiCode.Store(http.StatusForbidden)
	f.apiCT.Store("application/json; charset=utf-8")

	_, err := c.apiRequest(context.Background(), "revoked@example.com", http.MethodGet,
		"/api/permits/managedVehicle", "read", nil, nil)
	if errors.Is(err, ErrCouncilBusy) {
		t.Fatalf("a JSON 403 must not be classified busy, got %v", err)
	}
	if kind, _ := FailureOf(err); kind != FailRejected {
		t.Fatalf("kind = %v, want FailRejected", kind)
	}
	if _, blocked := c.cooldownFor("revoked@example.com"); blocked {
		t.Fatal("a genuine API refusal must not start a cooldown")
	}
}

// A push-back status from the IDM authorize endpoint must penalize the owner
// and short-circuit subsequent renews, exactly like the API path.
func TestSilentRenewPushbackPenalizes(t *testing.T) {
	f := newFakeCouncil(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, "idm@example.com")
	// Replace the authorize handler's behavior via a wrapper server is overkill;
	// instead point authURL at a 503 endpoint.
	f.mux.HandleFunc("/idm503/connect/authorize", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c.authURL = f.srv.URL + "/idm503/connect/authorize"

	err := c.Refresh(context.Background(), "idm@example.com")
	if !errors.Is(err, ErrCouncilBusy) {
		t.Fatalf("err = %v, want ErrCouncilBusy", err)
	}
	if _, blocked := c.cooldownFor("idm@example.com"); !blocked {
		t.Fatal("IDM push-back must start a cooldown")
	}
	// While cooling down, a renew must short-circuit without hitting the IDM.
	if err := c.Refresh(context.Background(), "idm@example.com"); !errors.Is(err, ErrCouncilBusy) {
		t.Fatalf("cooldown Refresh err = %v, want ErrCouncilBusy", err)
	}
}

// A sealed-password decrypt failure is deterministic (key rotated): Reconnect
// must retire to the manual re-link path, not loop as a transient error.
func TestReconnectDecryptFailureMapsToNoSavedPassword(t *testing.T) {
	f := newFakeCouncil(t)
	c, st, box := testClient(t, f)
	ctx := context.Background()
	sealedCookie, _ := box.Seal("Permits.IDM.Identity=abc")
	// A password sealed under a DIFFERENT key: Open fails forever.
	otherBox, _ := secretbox.New([]byte("ffffffffffffffffffffffffffffffff"))
	badPass, _ := otherBox.Seal("hunter2")
	if err := st.SaveCouncilSession(ctx, store.CouncilSession{Owner: "rot@example.com", Cookie: sealedCookie, Password: badPass}); err != nil {
		t.Fatal(err)
	}
	if err := c.Reconnect(ctx, "rot@example.com"); !errors.Is(err, ErrNoSavedPassword) {
		t.Fatalf("err = %v, want ErrNoSavedPassword", err)
	}
}

// A cookie the IDM deletes on renew (Max-Age=0 / past Expires) must be removed
// from the merged header, not carried forward as "name=".
func TestMergeSetCookieHonoursDeletion(t *testing.T) {
	got := mergeSetCookie("a=1; b=2; c=3", []*http.Cookie{
		{Name: "b", Value: "", MaxAge: -1},
		{Name: "c", Value: "", Expires: time.Now().Add(-time.Hour)},
		{Name: "d", Value: "4"},
	})
	if strings.Contains(got, "b=") || strings.Contains(got, "c=") {
		t.Fatalf("deleted cookies survived the merge: %q", got)
	}
	if !strings.Contains(got, "a=1") || !strings.Contains(got, "d=4") {
		t.Fatalf("live cookies lost in the merge: %q", got)
	}
}
