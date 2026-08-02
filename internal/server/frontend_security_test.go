package server

import (
	"encoding/base64"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/config"
)

// These tests exist because a broken CSP fails silently and invisibly to Go: the
// test suite never executes JavaScript, so a policy that blocks every inline
// script still renders a 200 with the right bytes in it. What can be checked
// mechanically is the contract between the header and the markup — that a fresh
// nonce is minted per response, that it reaches every <script> tag, and that no
// handler was left in an attribute where a nonce could never authorise it.

var (
	cspNonceRe  = regexp.MustCompile(`'nonce-([A-Za-z0-9+/=_-]+)'`)
	scriptTagRe = regexp.MustCompile(`(?s)<script[^>]*>`)
	// An on* handler attribute, in markup or in a Go template. Requires the quote so
	// prose in a comment ("this replaced an onclick= attribute") is not a hit.
	inlineHandlerRe = regexp.MustCompile(`(^|[\s"'])on[a-z]+\s*=\s*["']`)
)

// cspDirective pulls one directive out of a policy string.
func cspDirective(t *testing.T, policy, name string) string {
	t.Helper()
	for _, d := range strings.Split(policy, ";") {
		d = strings.TrimSpace(d)
		if strings.HasPrefix(d, name+" ") {
			return d
		}
	}
	t.Fatalf("CSP has no %s directive: %q", name, policy)
	return ""
}

// A reused nonce is worse than no nonce: it reads as containment while an injected
// <script nonce="…"> — the attacker only has to read one page to learn the value —
// runs with the policy's blessing.
func TestCSPScriptNonceIsFreshPerResponse(t *testing.T) {
	s := newAuthzServer(t)

	nonceOf := func() string {
		w := s.doReq("GET", "/", "", "", nil)
		m := cspNonceRe.FindStringSubmatch(w.Header().Get("Content-Security-Policy"))
		if m == nil {
			t.Fatalf("no nonce in CSP: %q", w.Header().Get("Content-Security-Policy"))
		}
		return m[1]
	}

	first, second := nonceOf(), nonceOf()
	if first == second {
		t.Fatalf("the same nonce %q was served twice; it must be minted per response", first)
	}
	for _, n := range []string{first, second} {
		b, err := base64.RawURLEncoding.DecodeString(n)
		if err != nil {
			t.Fatalf("nonce %q is not base64: %v", n, err)
		}
		if len(b) < 16 {
			t.Fatalf("nonce %q carries %d bytes, want at least 16", n, len(b))
		}
	}
}

// The header and the markup have to agree on every page, on every <script> tag.
// If they ever disagree the page still returns 200 and looks fine to a Go test,
// while in a browser the theme, the toast, the confirm dialog and htmx itself are
// all dead.
func TestEveryScriptTagCarriesTheResponseNonce(t *testing.T) {
	s := newAuthzServer(t)
	// A spread of the layout's rendering states: the public pages (which also pull in
	// the demo assets), and a signed-in path, which lands on the terms gate here.
	for _, path := range []string{"/", "/security", "/how", "/schedule"} {
		t.Run(path, func(t *testing.T) {
			email := ""
			if path == "/schedule" {
				email = "user@example.com"
			}
			w := s.doReq("GET", path, email, "", nil)
			if w.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", path, w.Code)
			}
			m := cspNonceRe.FindStringSubmatch(w.Header().Get("Content-Security-Policy"))
			if m == nil {
				t.Fatalf("no nonce in CSP: %q", w.Header().Get("Content-Security-Policy"))
			}
			nonce, body := m[1], w.Body.String()

			tags := scriptTagRe.FindAllString(body, -1)
			if len(tags) == 0 {
				t.Fatal("page rendered no <script> tags at all; this test would pass vacuously")
			}
			for _, tag := range tags {
				if !strings.Contains(tag, `nonce="`+nonce+`"`) {
					t.Errorf("script tag is not authorised by this response's nonce: %s", tag)
				}
			}
		})
	}
}

// script-src must not carry 'unsafe-inline'. Leaving it in would be doubly wrong:
// CSP3 makes a browser ignore it once a nonce is present, so it buys nothing, and
// it advertises a policy the app does not actually have.
func TestScriptSrcDropsUnsafeInline(t *testing.T) {
	s := newAuthzServer(t)
	w := s.doReq("GET", "/", "", "", nil)
	policy := w.Header().Get("Content-Security-Policy")

	script := cspDirective(t, policy, "script-src")
	if strings.Contains(script, "'unsafe-inline'") {
		t.Errorf("script-src still allows inline script: %q", script)
	}
	// 'unsafe-eval' is required, not an oversight: Alpine compiles every x-data /
	// @click / x-show expression with new Function, so removing it takes the whole
	// interactive UI apart on first use. Asserted here so the removal shows up as a
	// failing test rather than as a silently inert app.
	if !strings.Contains(script, "'unsafe-eval'") {
		t.Errorf("script-src lost 'unsafe-eval', which Alpine needs: %q", script)
	}
	// A nonce covers elements, never attributes, so the ~20 inline style= sites that
	// carry the colour language cannot be nonced and this must stay.
	if style := cspDirective(t, policy, "style-src"); !strings.Contains(style, "'unsafe-inline'") {
		t.Errorf("style-src lost 'unsafe-inline', which the inline style= attributes need: %q", style)
	}
}

// An on* attribute cannot be authorised by a nonce, so under the nonced policy it
// simply never fires — a button that looks fine and does nothing. Grep the embedded
// templates rather than trusting review: this is the failure mode most likely to be
// reintroduced by someone adding a button.
func TestTemplatesHaveNoInlineEventHandlers(t *testing.T) {
	err := fs.WalkDir(templateFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, e := templateFS.ReadFile(p)
		if e != nil {
			return e
		}
		for i, line := range strings.Split(string(b), "\n") {
			if inlineHandlerRe.MatchString(line) {
				t.Errorf("%s:%d has an inline event handler, which the CSP cannot authorise; "+
					"use a data- attribute and a delegated addEventListener instead:\n\t%s",
					p, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
	}
}

// Every <script> in the templates must be nonced at the point it is written. The
// fragment templates that handlers execute directly (notify-body, permit-body,
// legend, guest-body, qr-card, guest-req-status) render without layout.html and
// some are built from view models that have no Nonce field at all — so an inline
// script added to one of those would be unauthorised with nothing to fix it. This
// keeps that discovery at test time.
func TestEveryTemplateScriptTagIsNonced(t *testing.T) {
	const want = `{{with .Nonce}} nonce="{{.}}"{{end}}`
	err := fs.WalkDir(templateFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, e := templateFS.ReadFile(p)
		if e != nil {
			return e
		}
		src, seen := string(b), 0
		for _, tag := range scriptTagRe.FindAllString(src, -1) {
			seen++
			if !strings.Contains(tag, want) {
				t.Errorf("%s: <script> tag is missing %s — it would be blocked by the CSP:\n\t%s", p, want, tag)
			}
		}
		if p == "templates/layout.html" && seen == 0 {
			t.Errorf("%s: found no <script> tags; the regex has stopped matching and this test is vacuous", p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
	}
}

// messageWithLink builds markup by hand, outside html/template, so nothing applies
// the contextual URL check for it. HTMLEscapeString stops attribute breakout and
// says nothing about the scheme, which is what a javascript: href needs.
func TestMessageWithLinkRefusesUnsafeHref(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	const label = "Sign out"

	cases := []struct {
		href string
		safe bool
	}{
		{"/auth/logout", true},                    // the forward-auth default
		{"https://auth.example.com/logout", true}, // an operator's AUTH_LOGOUT_URL
		{"http://auth.example.com/logout", true},  // plaintext is the operator's call
		{"javascript:alert(1)", false},            //
		{"JavaScript:alert(1)", false},            // scheme matching is case-insensitive
		{"java\tscript:alert(1)", false},          // the classic control-character split
		{"data:text/html,<script>alert(1)</script>", false},
		{"vbscript:msgbox(1)", false},
		{"//evil.example.com/logout", false}, // scheme-relative: a different origin
		{`/\evil.example.com/logout`, false}, // browsers read the backslash as an authority
		{"https:///logout", false},           // http(s) with no host resolves nowhere useful
		{"logout", false},                    // relative to whatever path we happen to be on
		{"", false},
	}

	for _, c := range cases {
		w := httptest.NewRecorder()
		s.messageWithLink(w, http.StatusOK, "You declined the updated terms.", label, c.href, ".")
		body := w.Body.String()

		if got := strings.Contains(body, "<a href=\""+c.href+"\">"); got != c.safe {
			t.Errorf("href %q: link rendered = %v, want %v\n%s", c.href, got, c.safe, body)
		}
		if !c.safe && strings.Contains(body, label) {
			t.Errorf("href %q: refused link still rendered its label\n%s", c.href, body)
		}
		// Refusing the link must not lose the sentence — that is the whole page.
		if !strings.Contains(body, "You declined the updated terms.") {
			t.Errorf("href %q: the message itself went missing\n%s", c.href, body)
		}
	}
}

// An inline script inside the hx-boost'd <body> is blocked by the CSP on every
// boosted navigation, even though it carries the nonce in the template.
//
// hx-boost swaps the body's innerHTML, and htmx RE-CREATES any script element it
// finds in swapped content. A re-created script cannot inherit the nonce: browsers
// deliberately hide the nonce value from the DOM once the document is parsed, so the
// copied attribute is empty and the CSP refuses it. The page still works only by
// luck — both current scripts merely register globals that survive the swap — so the
// failure is silent, shows up as console noise, and would bite the first script that
// actually needs to run per-swap. Keep inline scripts in <head>, above the boost.
func TestNoInlineScriptInsideBoostedBody(t *testing.T) {
	b, err := templateFS.ReadFile("templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	// Match the real body TAG, not the first "<body" (a script in <head> mentions one
	// inside a JS string literal, and matching that made this test skip silently).
	loc := regexp.MustCompile(`<body\b[^>]*hx-boost`).FindStringIndex(src)
	if loc == nil {
		t.Skip("body is no longer hx-boosted; the re-creation hazard does not apply")
	}
	body := loc[0]
	for _, tag := range scriptTagRe.FindAllStringIndex(src, -1) {
		if tag[0] > body {
			t.Errorf("inline script at offset %d is inside the hx-boost'd body; htmx re-creates it on every boosted navigation and the CSP blocks it (move it into <head>):\n\t%s",
				tag[0], src[tag[0]:min(tag[1]+60, len(src))])
		}
	}
}
