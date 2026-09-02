package orikan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

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

// The tenant reports a refusal as a JSON ARRAY of message objects. Captured live
// on 2026-07-31 from a manageVehicle POST that was rejected. Before this was
// parsed the body was discarded and the user saw only "council returned 400",
// which says nothing they can act on.
func TestTenantErrorMessage(t *testing.T) {
	const live = `[{"Level":0,"Message":"Vehicle Registration has invalid pattern","ID":null,"LinkURL":null,"Title":null,"CustomMessage":null,"LinkLabel":null}]`
	if got := refusalMessage([]byte(live)); got != "Vehicle Registration has invalid pattern" {
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
		if got := refusalMessage([]byte(tc.body)); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}

	// Portal-controlled text reaches logs and notifications, so a refusal must not
	// be able to forge log lines with embedded newlines.
	got := refusalMessage([]byte("[{\"Message\":\"bad\\nJul 31 12:00:00 pstonn: forged\"}]"))
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("newlines survived into an error message: %q", got)
	}
}

// The home state written on an add or a state-less edit comes from the tenant
// descriptor as a CODE, mapped to the portal token here. A bare Client (tests, or
// an unset/unknown descriptor) falls back to VIC so today's single-tenant
// behaviour is unchanged.
func TestVehicleStateDefault(t *testing.T) {
	if c := New(Config{}, nil); c.homeCode != "VIC" || c.homeToken != "1" {
		t.Fatalf("default home = %q/%q, want VIC/1", c.homeCode, c.homeToken)
	}
	if c := New(Config{HomeState: "nsw"}, nil); c.homeCode != "NSW" || c.homeToken != "3" {
		t.Fatalf("configured home = %q/%q, want NSW/3", c.homeCode, c.homeToken)
	}
	if c := New(Config{HomeState: "ZZ"}, nil); c.homeCode != "VIC" || c.homeToken != "1" {
		t.Fatalf("unknown home = %q/%q, want fallback VIC/1", c.homeCode, c.homeToken)
	}
}

// emptyIsCredible must require every corroborating field to be EXPLICITLY present.
// A shape change that drops permitVehicleCount (or the permitVehicles array) while
// keeping permitNumber must NOT read as a credible empty permit.
func TestEmptyIsCredibleRequiresExplicitFields(t *testing.T) {
	zero := 0
	one := 1
	cases := []struct {
		name string
		mv   managedVehicleResp
		want bool
	}{
		{"count 0 and explicit empty array", managedVehicleResp{PermitNumber: "VPP1", PermitVehicleCount: &zero, PermitVehicles: []permitVehicle{}}, true},
		{"count field absent", managedVehicleResp{PermitNumber: "VPP1", PermitVehicles: []permitVehicle{}}, false},
		{"permitVehicles key absent", managedVehicleResp{PermitNumber: "VPP1", PermitVehicleCount: &zero}, false},
		{"permitNumber absent", managedVehicleResp{PermitVehicleCount: &zero, PermitVehicles: []permitVehicle{}}, false},
		{"count present but non-zero", managedVehicleResp{PermitNumber: "VPP1", PermitVehicleCount: &one, PermitVehicles: []permitVehicle{}}, false},
	}
	for _, c := range cases {
		if got := c.mv.emptyIsCredible(); got != c.want {
			t.Errorf("%s: emptyIsCredible = %v, want %v", c.name, got, c.want)
		}
	}
}

// A token-shape failure must classify as provider.FailUnexpected. Left unclassified, FailureOf
// defaults it to provider.FailTransient — and a transient verdict on a FLEET-WIDE shape change
// means every owner retries it on every warm tick instead of the operator being told.
func TestTokenShapeFailuresAreUnexpectedNotTransient(t *testing.T) {
	for name, body := range map[string]string{
		"no expires_in":     `{"access_token":"a","token_type":"Bearer"}`,
		"zero expires_in":   `{"access_token":"a","expires_in":0,"token_type":"Bearer"}`,
		"absurd expires_in": `{"access_token":"a","expires_in":999999,"token_type":"Bearer"}`,
		"wrong token_type":  `{"access_token":"a","expires_in":3600,"token_type":"Mac"}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, body)
			}))
			defer srv.Close()
			c := New(Config{Issuer: srv.URL + "/idm", APIBase: srv.URL + "/ssp-svc", ClientID: "t", RedirectURI: srv.URL + "/ssp/callback"}, nil)
			_, err := c.exchangeCode(context.Background(), "code", "verifier")
			if err == nil {
				t.Fatalf("%s should be refused", name)
			}
			if kind, _ := provider.FailureOf(err); kind != provider.FailUnexpected {
				t.Fatalf("%s classified as %v, want provider.FailUnexpected (transient would retry forever)", name, kind)
			}
		})
	}
}

// A 3xx from the permit API is the edge talking (a WAF interstitial, a
// maintenance bounce, a portal move), never the council refusing THIS permit. It
// must classify as transient: the generic "< 500 is a refusal" rule would park
// the permit for good and tell the household the council would not allow it.
func TestAPIRedirectIsTransientNotRefusal(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "https://edge.example/maintenance?return=SECRET-RETURN-URL")
				w.WriteHeader(status)
			}))
			defer srv.Close()
			c := New(Config{Issuer: srv.URL + "/idm", APIBase: srv.URL + "/ssp-svc", ClientID: "t", RedirectURI: srv.URL + "/ssp/callback"}, nil)
			ss := &session{Cookie: "c=1", AccessToken: "tok", TokenExpiry: time.Now().Add(time.Hour)}
			_, err := c.managedVehicle(context.Background(), ss, provider.PermitRef{ID: "1"}, provider.OpSetVehicle)
			if err == nil {
				t.Fatal("a redirect is not a permit record")
			}
			if kind, op := provider.FailureOf(err); kind != provider.FailTransient || op != provider.OpSetVehicle {
				t.Fatalf("classified %v/%v, want FailTransient/%v (a refusal is parked and blamed on the household)", kind, op, provider.OpSetVehicle)
			}
			if !strings.Contains(err.Error(), "edge.example/maintenance") || strings.Contains(err.Error(), "SECRET-RETURN-URL") {
				t.Fatalf("error should name the redirect target but not its query: %v", err)
			}
		})
	}
}

// A silent renew's redirect only means "session expired" when it is
// IdentityServer's own answer: an error= delivered back to the registered
// redirect_uri. Any other code-less redirect — an edge challenge, a login page we
// never asked for, a bare callback — is unexpected and transient, because
// ErrSessionExpired triggers fleet-wide reconnects and unlinks every owner
// without a saved password.
func TestSilentRenewRedirectExpiryNeedsRedirectURIAndError(t *testing.T) {
	cases := []struct {
		name, location string
		wantExpired    bool
		wantCode       string
	}{
		{"error back to redirect_uri", "{redirect}?error=login_required&state=s", true, ""},
		{"relative error back to redirect_uri", "/ssp/callback?error=interaction_required", true, ""},
		{"code back to redirect_uri", "{redirect}?code=abc&state=s", false, "abc"},
		{"edge challenge with no code", "https://edge.example/challenge?ref=1", false, ""},
		{"error on another host", "https://edge.example/ssp/callback?error=login_required", false, ""},
		{"error on another path", "{base}/elsewhere?error=login_required", false, ""},
		{"bounce to a login page", "{base}/idm/Account/Login?ReturnUrl=SECRET-RETURN-URL", false, ""},
		{"redirect_uri with neither code nor error", "{redirect}?state=s", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var base string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				loc := strings.NewReplacer("{redirect}", base+"/ssp/callback", "{base}", base).Replace(tc.location)
				w.Header().Set("Location", loc)
				w.WriteHeader(http.StatusFound)
			}))
			defer srv.Close()
			base = srv.URL
			c := New(Config{Issuer: base + "/idm", APIBase: base + "/ssp-svc", ClientID: "t", RedirectURI: base + "/ssp/callback"}, nil)
			code, _, _, err := c.authorizeWithCookie(context.Background(), "c=1")
			switch {
			case tc.wantCode != "":
				if err != nil || code != tc.wantCode {
					t.Fatalf("code = %q, err = %v; want %q", code, err, tc.wantCode)
				}
			case tc.wantExpired:
				if !errors.Is(err, provider.ErrSessionExpired) {
					t.Fatalf("err = %v, want ErrSessionExpired", err)
				}
			default:
				if err == nil || errors.Is(err, provider.ErrSessionExpired) {
					t.Fatalf("err = %v; an unrecognised redirect must not retire the session", err)
				}
				if kind, _ := provider.FailureOf(err); kind != provider.FailTransient {
					t.Fatalf("classified %v, want FailTransient (retry, don't alarm)", kind)
				}
				if strings.Contains(err.Error(), "SECRET-RETURN-URL") {
					t.Fatalf("error leaks the redirect query: %v", err)
				}
			}
		})
	}
}
