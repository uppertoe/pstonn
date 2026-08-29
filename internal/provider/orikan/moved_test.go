package orikan

import (
	"context"
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

// The vehicle-state id written on an add or a state-less edit comes from the
// tenant descriptor; a bare Client (tests, or an unset descriptor) falls back to
// VIC so today's single-tenant behaviour is unchanged.
func TestVehicleStateDefault(t *testing.T) {
	if got := New(Config{}, nil).vehicleState; got != "1" {
		t.Fatalf("default vehicleState = %q, want VIC (1)", got)
	}
	if got := New(Config{DefaultVehicleState: "3"}, nil).vehicleState; got != "3" {
		t.Fatalf("configured vehicleState = %q, want 3", got)
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
