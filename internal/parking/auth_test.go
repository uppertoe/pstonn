package parking

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseLoginForm(t *testing.T) {
	// Mirrors the shape of the council's Duende login page: a form posting to a
	// returnurl action, with the antiforgery token and hidden fields alongside
	// the visible Username/Password inputs.
	page := `
<html><body>
<form action="/idm?returnurl=%2Fidm%2Fconnect%2Fauthorize%2Fcallback&amp;client_id=ePermits.ssp.web" method="post">
  <input type="hidden" name="ReturnURL" value="/idm/connect/authorize/callback?client_id=ePermits.ssp.web" />
  <input type="hidden" name="LocalProvider" value="local" />
  <input id="Username" name="Username" type="text" value="" />
  <input id="Password" name="Password" type="password" value="" />
  <button type="submit">Sign in</button>
  <input name="__RequestVerificationToken" type="hidden" value="CfDJ8-abc_TOKEN-123" />
</form>
</body></html>`

	action, fields := parseLoginForm(page)
	// Percent-encoding (%2F) is left intact for url.Parse; only HTML entities
	// (&amp;) are unescaped.
	if want := "/idm?returnurl=%2Fidm%2Fconnect%2Fauthorize%2Fcallback&client_id=ePermits.ssp.web"; action != want {
		t.Fatalf("action = %q, want %q", action, want)
	}
	if got := fields["__RequestVerificationToken"]; got != "CfDJ8-abc_TOKEN-123" {
		t.Fatalf("antiforgery token = %q, want the hidden value", got)
	}
	if got, ok := fields["ReturnURL"]; !ok || !strings.Contains(got, "authorize/callback") {
		t.Fatalf("ReturnURL = %q (ok=%v), want the callback path", got, ok)
	}
	// Visible inputs are present (empty) so the caller can fill them.
	if _, ok := fields["Username"]; !ok {
		t.Fatalf("Username field not harvested")
	}
	if _, ok := fields["Password"]; !ok {
		t.Fatalf("Password field not harvested")
	}
}

func TestMergeSetCookie(t *testing.T) {
	existing := "idsrv.session=SESS1; Permits.IDM.Identity=ID_OLD; .AspNetCore.Antiforgery.X=AF1"
	// The authorize response rotates the identity cookie and leaves the rest.
	set := []*http.Cookie{{Name: "Permits.IDM.Identity", Value: "ID_NEW"}}

	got := mergeSetCookie(existing, set)

	if !strings.Contains(got, "Permits.IDM.Identity=ID_NEW") {
		t.Fatalf("rotated cookie not applied: %q", got)
	}
	if strings.Contains(got, "ID_OLD") {
		t.Fatalf("stale cookie value survived: %q", got)
	}
	if !strings.Contains(got, "idsrv.session=SESS1") || !strings.Contains(got, ".AspNetCore.Antiforgery.X=AF1") {
		t.Fatalf("untouched cookies were dropped: %q", got)
	}
	// No duplicate entry for the rotated cookie.
	if strings.Count(got, "Permits.IDM.Identity=") != 1 {
		t.Fatalf("duplicate cookie entry: %q", got)
	}
}

func TestMergeSetCookieNoChange(t *testing.T) {
	existing := "Permits.IDM.Identity=ID1"
	if got := mergeSetCookie(existing, nil); got != existing {
		t.Fatalf("mergeSetCookie with no Set-Cookie changed the header: %q", got)
	}
}
