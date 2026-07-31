package parking

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
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

// C4: quoting style is cosmetic, so a page that switches to single quotes, drops
// the quotes, or spaces its attributes differently must still be harvested. The
// alternative was every login failing as ErrLoginRejected — users told their
// password was wrong and every saved session deleted, over a template tidy-up.
func TestParseLoginFormQuotingStyles(t *testing.T) {
	page := `
<form method='post' action='/idm?returnurl=%2Fcb'>
  <input type='hidden' name='ReturnURL' value='/cb?client_id=x' />
  <input name = "LocalProvider" value = "local">
  <input id=Username name=Username type=text value="">
  <input name='Password' type='password' value=''>
  <input name="__RequestVerificationToken" type=hidden value='CfDJ8-single-quoted'>
  <input data-name="decoy" name="Real" value="kept">
</form>`

	action, fields := parseLoginForm(page)
	if want := "/idm?returnurl=%2Fcb"; action != want {
		t.Fatalf("action = %q, want %q", action, want)
	}
	for name, want := range map[string]string{
		"ReturnURL":      "/cb?client_id=x",
		"LocalProvider":  "local",
		"Username":       "",
		"Password":       "",
		fieldAntiforgery: "CfDJ8-single-quoted",
		"Real":           "kept",
	} {
		got, ok := fields[name]
		if !ok {
			t.Fatalf("field %q not harvested from %v", name, fields)
		}
		if got != want {
			t.Fatalf("field %q = %q, want %q", name, got, want)
		}
	}
	// `data-name="decoy"` must not be mistaken for the field's own name.
	if _, ok := fields["decoy"]; ok {
		t.Fatalf("data-name was read as name: %v", fields)
	}
	if err := checkLoginForm(fields); err != nil {
		t.Fatalf("a well-formed single-quoted form must be accepted: %v", err)
	}
}

// C4: an unrecognised page must NOT come back as ErrLoginRejected. That error is
// "your password is wrong": it burns the user's attempt throttle and makes the
// scheduler delete every saved session, so a portal HTML change would masquerade
// as a fleet-wide credential failure.
func TestCheckLoginFormRejectsUnrecognisedShapes(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]string
	}{
		{"no antiforgery token", map[string]string{"Username": "", "Password": ""}},
		{"empty antiforgery token", map[string]string{fieldAntiforgery: "", "Username": "", "Password": ""}},
		{"no username input", map[string]string{fieldAntiforgery: "t", "Password": ""}},
		{"no password input", map[string]string{fieldAntiforgery: "t", "Username": ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkLoginForm(tc.fields)
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			if !errors.Is(err, ErrLoginFormUnrecognised) {
				t.Fatalf("err = %v, want ErrLoginFormUnrecognised", err)
			}
			if errors.Is(err, ErrLoginRejected) {
				t.Fatal("a page-shape problem must never surface as ErrLoginRejected")
			}
		})
	}
}

// C4: a page-shape failure must land where the scheduler keeps the session and the
// saved password (its transient default) and the link handler stops short of
// blaming the password — and must be classified FailUnexpected, which is the
// "council changed its API" signal, not FailRejected.
func TestLinkShapeErrClassification(t *testing.T) {
	c := &Client{}
	err := c.linkShapeErr(errors.New("boom"))
	if kind, op := FailureOf(err); kind != FailUnexpected || op != opLogin {
		t.Fatalf("FailureOf = (%v, %q), want (FailUnexpected, %q)", kind, op, opLogin)
	}
	// The classifications the scheduler acts on destructively must not match.
	for _, sentinel := range []error{ErrLoginRejected, ErrNoSavedPassword, ErrSessionExpired, ErrCouncilBusy} {
		if errors.Is(err, sentinel) {
			t.Fatalf("a page-shape failure must not satisfy errors.Is(_, %v)", sentinel)
		}
	}
}

// C1: this is the finding that exfiltrates plaintext council passwords. An
// absolute form action on a host the council configuration never named must be
// refused before the password is ever assembled into a request body.
func TestResolveActionPinsToCouncilHosts(t *testing.T) {
	allowed := map[string]bool{"permits.council.example": true, "sso.council.example": true}
	base, err := url.Parse("https://permits.council.example/idm/Account/Login?returnurl=%2Fcb")
	if err != nil {
		t.Fatal(err)
	}

	// Relative and same-host absolute actions resolve as before.
	for _, action := range []string{
		"",
		"/idm?returnurl=%2Fcb",
		"https://permits.council.example/idm",
		"https://sso.council.example/idm", // a second configured council host
	} {
		got, err := resolveAction(base, action, allowed)
		if err != nil {
			t.Fatalf("resolveAction(%q) = %v, want it accepted", action, err)
		}
		if u, perr := url.Parse(got); perr != nil || !allowed[u.Host] {
			t.Fatalf("resolveAction(%q) = %q, which is not on a council host", action, got)
		}
	}

	// Anything that would take the password elsewhere is refused.
	for _, action := range []string{
		"https://attacker.example/",
		"//attacker.example/idm",                        // protocol-relative
		"http://permits.council.example/idm",            // scheme downgrade, right host
		"https://permits.council.example.attacker.test", // suffix lookalike
	} {
		got, err := resolveAction(base, action, allowed)
		if !errors.Is(err, ErrLoginOffHost) {
			t.Fatalf("resolveAction(%q) = %q, %v; want ErrLoginOffHost", action, got, err)
		}
		if got != "" {
			t.Fatalf("resolveAction(%q) returned a target (%q) alongside its refusal", action, got)
		}
	}

	// A login page served off-host is refused even with a relative action, because
	// then the base URL itself is the POST target.
	offHost, _ := url.Parse("https://attacker.example/Account/Login")
	if _, err := resolveAction(offHost, "/idm", allowed); !errors.Is(err, ErrLoginOffHost) {
		t.Fatalf("an off-host login page must be refused, got %v", err)
	}
}

// C1: the configured hosts are the only ones the flow may touch, and they come
// only from configuration — never from the scraped page.
func TestLoginHosts(t *testing.T) {
	c := &Client{
		authURL:     "https://permits.council.example/idm/connect/authorize",
		tokenURL:    "https://permits.council.example/idm/connect/token",
		loginURL:    "https://permits.council.example/idm/Account/Login",
		origin:      "https://permits.council.example",
		redirectURI: "https://spa.council.example/ssp/callback",
	}
	hosts := c.loginHosts()
	for _, want := range []string{"permits.council.example", "spa.council.example"} {
		if !hosts[want] {
			t.Fatalf("host %q missing from %v", want, hosts)
		}
	}
	if len(hosts) != 2 {
		t.Fatalf("unexpected extra hosts: %v", hosts)
	}
	// An unconfigured client has nothing to pin to, and Link must refuse rather
	// than post a password to whatever the page names.
	if len((&Client{}).loginHosts()) != 0 {
		t.Fatal("an unconfigured client must yield no allowed hosts")
	}
}

// C6: the IDM sets several cookies whose names all START with the session
// cookie's name. A substring test let a FAILED login report success — sealing a
// useless cookie and storing the user's council password for a session that never
// existed.
func TestHasCookieNamedExactMatch(t *testing.T) {
	siblings := ".AspNetCore.Antiforgery.X=AF1; Permits.IDM.Identity.External=EXT; Permits.IDM.Identity.Nonce=N1"
	if hasCookieNamed(siblings, councilSessionCookie) {
		t.Fatalf("prefixed siblings were accepted as a session: %q", siblings)
	}
	if !strings.Contains(siblings, councilSessionCookie) {
		t.Fatal("test fixture is wrong: it must be one a substring check would accept")
	}
	if !hasCookieNamed("idsrv.session=S; Permits.IDM.Identity=ID1; x=y", councilSessionCookie) {
		t.Fatal("a real session cookie was not recognised")
	}
	// A name with no value is the server CLEARING the cookie, not a session.
	if hasCookieNamed("Permits.IDM.Identity=", councilSessionCookie) {
		t.Fatal("an empty session cookie value was accepted")
	}
	// Leading/trailing space around the pair is normal in a serialised header.
	if !hasCookieNamed("a=1;   Permits.IDM.Identity=ID1  ", councilSessionCookie) {
		t.Fatal("whitespace around the pair defeated the match")
	}
}

// C7: portal-controlled text reaches log.Printf through error strings, so a
// newline would let the portal forge log lines and 1 MiB of body would land in the
// journal on every attempt.
func TestSafeExcerpt(t *testing.T) {
	got := safeExcerpt("boom\nJul 30 12:00:00 pstonn[1]: forged line\r\n\tmore")
	if strings.ContainsAny(got, "\n\r\t") {
		t.Fatalf("control characters survived: %q", got)
	}
	long := safeExcerpt(strings.Repeat("A", 5000))
	if len(long) > maxPortalExcerpt+len("…(truncated)") {
		t.Fatalf("excerpt not truncated: %d bytes", len(long))
	}
	if !strings.HasSuffix(long, "(truncated)") {
		t.Fatalf("truncation not marked: %q", long)
	}
	// Truncating mid-rune must not leave invalid UTF-8 behind.
	if !utf8.ValidString(safeExcerpt(strings.Repeat("é", 500))) {
		t.Fatal("truncation produced invalid UTF-8")
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
