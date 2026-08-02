package parking

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
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
	apiBody atomic.Value // raw JSON the managedVehicle endpoint returns; "" = the canned record
}

func newFakeCouncil(t *testing.T) *fakeCouncil {
	t.Helper()
	f := &fakeCouncil{mux: http.NewServeMux()}
	f.apiCT.Store("text/html")
	f.apiBody.Store("")
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
		if raw := f.apiBody.Load().(string); raw != "" {
			io.WriteString(w, raw)
			return
		}
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
	return clientAt(t, f.srv.URL)
}

// clientAt builds a Client whose every council endpoint lives on base, with a
// real store and box behind it.
func clientAt(t *testing.T, base string) (*Client, *store.Store, *secretbox.Box) {
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

// An HTML 403 is Azure Front Door push-back: transient, penalized, ErrCouncilBusy.
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

// ---- C1: the credential POST is pinned to the council's own hosts ----

// linkFake is a fake council for the headless-login flow: an authorize endpoint
// that bounces to a sign-in page, and a sign-in page whose form action and
// response cookies the test controls.
type linkFake struct {
	srv *httptest.Server

	action        string         // written into the form; "" omits the attribute entirely
	loginRedirect string         // where the authorize GET sends us; "" = this server's own page
	cookies       []*http.Cookie // what the sign-in POST sets

	mu     sync.Mutex
	posted url.Values // the form body the sign-in endpoint received
}

func newLinkFake(t *testing.T) *linkFake {
	t.Helper()
	f := &linkFake{cookies: []*http.Cookie{
		{Name: "idsrv.session", Value: "S1", Path: "/"},
		{Name: councilSessionCookie, Value: "ID1", Path: "/"},
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("/idm/connect/authorize", func(w http.ResponseWriter, r *http.Request) {
		to := f.loginRedirect
		if to == "" {
			to = "/idm/Account/Login?returnurl=%2Fidm%2Fcb"
		}
		http.Redirect(w, r, to, http.StatusFound)
	})
	mux.HandleFunc("/idm/Account/Login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			f.mu.Lock()
			f.posted = r.PostForm
			f.mu.Unlock()
			for _, ck := range f.cookies {
				http.SetCookie(w, ck)
			}
			return
		}
		act := ""
		if f.action != "" {
			act = ` action="` + f.action + `"`
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body><form method="post"%s>
<input type="hidden" name="__RequestVerificationToken" value="CfDJ8-tok">
<input name="Username" type="text" value="">
<input name="Password" type="password" value="">
</form></body></html>`, act)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *linkFake) postedForm() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.posted
}

// exfilServer stands in for wherever a hostile form action points, and records
// anything that reaches it.
func exfilServer(t *testing.T) (*httptest.Server, func() string) {
	t.Helper()
	var got atomic.Value
	got.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		got.Store(r.URL.String() + "|" + string(b))
	}))
	t.Cleanup(srv.Close)
	return srv, func() string { return got.Load().(string) }
}

// The baseline: an ordinary login on the configured host still works end to end,
// so the host pinning below is refusing the right thing and not everything.
func TestLinkPostsCredentialsToCouncilHost(t *testing.T) {
	f := newLinkFake(t)
	c, st, _ := clientAt(t, f.srv.URL)

	if err := c.Link(context.Background(), "ok@example.com", "ok@example.com", "hunter2", false, true); err != nil {
		t.Fatalf("Link = %v, want success", err)
	}
	form := f.postedForm()
	if form.Get("Password") != "hunter2" || form.Get("Username") != "ok@example.com" {
		t.Fatalf("credentials not posted to the council: %v", form)
	}
	if form.Get("__RequestVerificationToken") != "CfDJ8-tok" {
		t.Fatalf("antiforgery token not replayed: %v", form)
	}
	if cs, err := st.GetCouncilSession(context.Background(), "ok@example.com"); err != nil || cs.Cookie == "" {
		t.Fatalf("session not stored: %+v, %v", cs, err)
	}
}

// C1: an absolute form action on a host the council configuration never named is
// the plaintext-password exfiltration path. Nothing may be sent, and the failure
// must not read as a rejected password.
func TestLinkRefusesOffHostFormAction(t *testing.T) {
	exfil, leaked := exfilServer(t)
	f := newLinkFake(t)
	f.action = exfil.URL + "/steal"
	c, st, _ := clientAt(t, f.srv.URL)

	err := c.Link(context.Background(), "v@example.com", "v@example.com", "hunter2", true, true)
	if !errors.Is(err, ErrLoginOffHost) {
		t.Fatalf("Link = %v, want ErrLoginOffHost", err)
	}
	if got := leaked(); got != "" {
		t.Fatalf("the password left the server: %q", got)
	}
	if f.postedForm() != nil {
		t.Fatalf("credentials were posted anyway: %v", f.postedForm())
	}
	// The user is not told their password is wrong, and nothing is stored.
	if errors.Is(err, ErrLoginRejected) {
		t.Fatal("an off-host action must not be reported as a rejected login")
	}
	if _, err := st.GetCouncilSession(context.Background(), "v@example.com"); err == nil {
		t.Fatal("a refused login stored a session")
	}
}

// C1: an open redirect on the portal moves the URL the form action resolves
// against, so the redirect policy has to refuse it too — otherwise the host check
// is bypassed without touching the page's HTML at all.
func TestLinkRefusesOffHostRedirect(t *testing.T) {
	exfil, leaked := exfilServer(t)
	f := newLinkFake(t)
	f.loginRedirect = exfil.URL + "/Account/Login"
	c, _, _ := clientAt(t, f.srv.URL)

	err := c.Link(context.Background(), "r@example.com", "r@example.com", "hunter2", true, true)
	if !errors.Is(err, ErrLoginOffHost) {
		t.Fatalf("Link = %v, want ErrLoginOffHost", err)
	}
	// The GET that was refused carries no credentials, but it must not have been
	// followed either: the jar's session cookies would have gone with it.
	if got := leaked(); got != "" {
		t.Fatalf("the login flow followed the portal off-host: %q", got)
	}
}

// C6: the IDM sets siblings whose names all begin with the session cookie's name,
// so a failed login can leave one behind. Reporting that as success sealed a
// useless cookie AND stored the user's council password.
func TestLinkRejectsPrefixedSiblingCookieOnly(t *testing.T) {
	f := newLinkFake(t)
	f.cookies = []*http.Cookie{
		{Name: councilSessionCookie + ".External", Value: "EXT", Path: "/"},
		{Name: councilSessionCookie + ".Nonce", Value: "N1", Path: "/"},
		{Name: ".AspNetCore.Antiforgery.X", Value: "AF1", Path: "/"},
	}
	c, st, _ := clientAt(t, f.srv.URL)

	err := c.Link(context.Background(), "sib@example.com", "sib@example.com", "hunter2", true, true)
	if !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("Link = %v, want ErrLoginRejected", err)
	}
	if _, err := st.GetCouncilSession(context.Background(), "sib@example.com"); err == nil {
		t.Fatal("a login that established no session stored one anyway (and with it the password)")
	}
}

// C4: a page whose antiforgery token is present but EMPTY must fail as a page
// shape problem, not as ErrLoginRejected — and the password must not be sent.
func TestLinkRefusesEmptyAntiforgeryToken(t *testing.T) {
	f := newLinkFake(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<form method="post"><input name="__RequestVerificationToken" value="">
<input name="Username" value=""><input name="Password" value=""></form>`)
	}))
	defer srv.Close()
	c, _, _ := clientAt(t, f.srv.URL)
	c.authURL = srv.URL + "/idm/connect/authorize" // serves the page directly

	err := c.Link(context.Background(), "af@example.com", "af@example.com", "hunter2", true, true)
	if !errors.Is(err, ErrLoginFormUnrecognised) {
		t.Fatalf("Link = %v, want ErrLoginFormUnrecognised", err)
	}
	if errors.Is(err, ErrLoginRejected) {
		t.Fatal("an unusable page must not be reported as a rejected password")
	}
	if kind, _ := FailureOf(err); kind != FailUnexpected {
		t.Fatalf("kind = %v, want FailUnexpected (the operator-alert classification)", kind)
	}
}

// ---- C2: an HTML answer to a prompt=none authorize means the session is gone ----

// The portal answering with a rendered page instead of a redirect is an expiry, so
// recoverOrRetire fires and the user is prompted to re-link. Genuine transients
// (5xx, push-back) must NOT be swept into that, or a healthy session gets retired.
func TestSilentRenewClassifiesAuthorizeAnswers(t *testing.T) {
	const owner = "html@example.com"
	f := newFakeCouncil(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)

	var status atomic.Int64
	var ct atomic.Value
	f.mux.HandleFunc("/idm-page/connect/authorize", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct.Load().(string))
		w.WriteHeader(int(status.Load()))
		io.WriteString(w, "<!DOCTYPE html><html><body><form>Sign in</form></body></html>")
	})
	c.authURL = f.srv.URL + "/idm-page/connect/authorize"

	cases := []struct {
		name    string
		code    int
		ct      string
		wantErr error // nil = "an error that is neither expiry nor busy"
	}{
		{"200 html login page", 200, "text/html; charset=utf-8", ErrSessionExpired},
		{"200 html mislabelled", 200, "application/octet-stream", ErrSessionExpired},
		{"500 with an html error page", 500, "text/html", nil},
		{"503 push-back", 503, "text/html", ErrCouncilBusy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status.Store(int64(tc.code))
			ct.Store(tc.ct)
			c.clearPenalty(owner) // each case starts outside any cooldown
			err := c.Refresh(context.Background(), owner)
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			switch tc.wantErr {
			case nil:
				if errors.Is(err, ErrSessionExpired) {
					t.Fatalf("a %d must stay transient, not retire the session: %v", tc.code, err)
				}
				if errors.Is(err, ErrCouncilBusy) {
					t.Fatalf("a %d is not push-back: %v", tc.code, err)
				}
			default:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			}
		})
	}
}

// ---- C3: an empty vehicle list needs corroborating evidence ----

// "No vehicle" and "we did not understand the response" decode identically, and
// believing the second writes an empty active registration plus an activity row
// claiming the user changed their plate at the council portal themselves.
func TestCurrentVehicleEmptyListNeedsCorroboration(t *testing.T) {
	const owner = "shape@example.com"
	f := newFakeCouncil(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)
	p := model.Permit{CouncilPermitID: "1"}

	// A response that identifies the permit and says the count is zero is believed.
	f.apiBody.Store(`{"permitNumber":"VPP1","permitVehicleCount":0,"maxVehicles":1,"permitVehicles":[]}`)
	if reg, err := c.CurrentVehicle(context.Background(), owner, p); err != nil || reg != "" {
		t.Fatalf("a corroborated empty permit = %q, %v; want \"\", nil", reg, err)
	}

	// Anything else is an unexpected shape, never an empty plate.
	for _, body := range []string{
		`{}`,
		`[]`,
		`{"permitVehicles":[]}`,
		`{"permitNumber":"VPP1","permitVehicleCount":2,"permitVehicles":[]}`, // self-contradictory
	} {
		f.apiBody.Store(body)
		reg, err := c.CurrentVehicle(context.Background(), owner, p)
		if err == nil {
			t.Fatalf("body %s: got %q, nil; want an unexpected-shape error", body, reg)
		}
		if kind, _ := FailureOf(err); kind != FailUnexpected {
			t.Fatalf("body %s: kind = %v, want FailUnexpected", body, kind)
		}
		if reg != "" {
			t.Fatalf("body %s: returned a plate (%q) alongside its error", body, reg)
		}
	}
}

// C3: a shape mismatch must not harden into "the permit has no vehicle to
// change", which is a durable refusal that tells the user to act and never
// retries.
func TestSetVehicleShapeMismatchIsNotADurableRefusal(t *testing.T) {
	const owner = "set@example.com"
	f := newFakeCouncil(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)
	p := model.Permit{CouncilPermitID: "1"}

	f.apiBody.Store(`{}`)
	err := c.SetVehicle(context.Background(), owner, p, "ABC123")
	if kind, _ := FailureOf(err); kind != FailUnexpected {
		t.Fatalf("kind = %v (%v), want FailUnexpected", kind, err)
	}
	if err != nil && strings.Contains(err.Error(), "no vehicle to change") {
		t.Fatalf("a shape mismatch became the durable refusal: %v", err)
	}

	// A corroborated empty permit IS that refusal, and stays one.
	f.apiBody.Store(`{"permitNumber":"VPP1","permitVehicleCount":0,"permitVehicles":[]}`)
	err = c.SetVehicle(context.Background(), owner, p, "ABC123")
	if kind, _ := FailureOf(err); kind != FailRejected {
		t.Fatalf("kind = %v (%v), want FailRejected", kind, err)
	}
	if err == nil || !strings.Contains(err.Error(), "no vehicle to change") {
		t.Fatalf("err = %v, want the no-vehicle refusal", err)
	}
}

// A plate that differs only in whitespace/case is the SAME car (model.SamePlate),
// so SetVehicle must treat it as already-allocated and report success — not send a
// pointless mutation and then fail confirmation. Under the old strings.EqualFold
// checks, "ABC 123" vs "ABC123" diverged: the pre-read was not a no-op and the
// post-write confirm declared a durable mismatch for the correct car.
func TestSetVehicleAcceptsWhitespaceVariantAsAlreadySet(t *testing.T) {
	const owner = "space@example.com"
	f := newFakeCouncil(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)
	p := model.Permit{CouncilPermitID: "1"}

	// The council's own record shows the plate with a space; the target has none.
	f.apiBody.Store(`{"permitNumber":"VPP1","permitVehicleCount":1,"maxVehicles":1,"canEditOrDeleteVehicle":true,"permitVehicles":[{"PKPermitVehicleDetailID":1,"RegistrationNumber":"ABC 123","FKVehicleStateID":"1"}]}`)
	if err := c.SetVehicle(context.Background(), owner, p, "ABC123"); err != nil {
		t.Fatalf("a whitespace-only variant should be treated as already set, got %v", err)
	}
}

// The council reports a refusal as a JSON ARRAY of message objects. Captured live
// on 2026-07-31 from a manageVehicle POST that was rejected. Before this was
// parsed the body was discarded and the user saw only "council returned 400",
// which says nothing they can act on.
func TestCouncilErrorMessage(t *testing.T) {
	const live = `[{"Level":0,"Message":"Vehicle Registration has invalid pattern","ID":null,"LinkURL":null,"Title":null,"CustomMessage":null,"LinkLabel":null}]`
	if got := councilErrorMessage([]byte(live)); got != "Vehicle Registration has invalid pattern" {
		t.Errorf("live refusal body parsed to %q", got)
	}

	for name, tc := range map[string]struct{ body, want string }{
		"custom message wins":     {`[{"Message":"raw","CustomMessage":"Friendlier wording"}]`, "Friendlier wording"},
		"blank custom falls back": {`[{"Message":"raw","CustomMessage":"  "}]`, "raw"},
		"multiple joined":         {`[{"Message":"one"},{"Message":"two"}]`, "one; two"},
		"empty array":             {`[]`, ""},
		"not an array":            {`{"Message":"nope"}`, ""},
		"not json":                {`<html>blocked</html>`, ""},
		"all messages blank":      {`[{"Message":"","CustomMessage":""}]`, ""},
	} {
		if got := councilErrorMessage([]byte(tc.body)); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}

	// Portal-controlled text reaches logs and notifications, so a refusal must not
	// be able to forge log lines with embedded newlines.
	got := councilErrorMessage([]byte("[{\"Message\":\"bad\\nJul 31 12:00:00 pstonn: forged\"}]"))
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("newlines survived into an error message: %q", got)
	}
}
