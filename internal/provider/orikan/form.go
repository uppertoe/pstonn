package orikan

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// The portal's sign-in page double-quotes its attribute values today, but quoting
// style is cosmetic: a template tidy-up, a minifier, or a framework upgrade can
// switch to single quotes or drop the quotes entirely without changing the page's
// meaning. Matching only double quotes made such a change indistinguishable from
// a wrong password — every login would have failed as ErrLoginRejected, telling
// users their password was wrong, burning their attempt throttle, and driving
// the scheduler to delete every saved session across the fleet. All three styles
// are therefore accepted.
//
// The attribute patterns require WHITESPACE before the attribute name rather than
// a word boundary, so `data-name=` can no longer be mistaken for `name=` and
// hijack a field (a `\b` matches after the hyphen).
var (
	reInputTag = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	reFormTag  = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	reNameAttr = regexp.MustCompile("(?is)\\sname\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'`=<>]+))")
	reValAttr  = regexp.MustCompile("(?is)\\svalue\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'`=<>]+))")
	reActAttr  = regexp.MustCompile("(?is)\\saction\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'`=<>]+))")
)

// The field names the portal's sign-in form uses. Hardcoding them is fine — they
// are what a captured, server-accepted POST contained. Proceeding when they are
// ABSENT is not, which is what checkLoginForm is for.
const (
	fieldUsername    = "Username"
	fieldPassword    = "Password"
	fieldAntiforgery = "__RequestVerificationToken"
)

// sessionCookie is the IdentityServer session cookie whose presence means a
// headless login actually established a session.
const sessionCookie = "Permits.IDM.Identity"

// parseLoginForm extracts the action and <input> name/value pairs of the login
// FORM from the page (values HTML-unescaped). It is intentionally lenient, a regex
// over a stable server-rendered ASP.NET form rather than a full HTML parse; what it
// harvests is then checked by checkLoginForm before anything is submitted.
//
// Crucially it is FORM-SCOPED: it returns the action and inputs of the form that
// actually carries the credential (Password) input, not the first form's action
// married to every input on the page. A decorative form placed ABOVE the sign-in
// form — a cookie banner, a language selector, a site search, all of which a routine
// portal template edit could add — would otherwise donate its action while the real
// credential inputs were harvested from elsewhere, so this client would POST the
// user's plaintext password to that unrelated endpoint and then misread the missing
// session cookie as a wrong password (a fleet-wide unlink over a cosmetic change).
// A page with no credential-bearing form yields an empty result, which checkLoginForm
// turns into ErrLoginFormUnrecognised.
func parseLoginForm(page string) (action string, fields map[string]string) {
	fields = map[string]string{}
	formTags := reFormTag.FindAllStringIndex(page, -1)
	for i, loc := range formTags {
		openEnd := loc[1] // just past this form's "<form ...>" tag
		// This form's body runs to its </form>, but never past where the NEXT form
		// begins (so a missing close tag cannot swallow the following form's inputs).
		spanEnd := len(page)
		if i+1 < len(formTags) {
			spanEnd = formTags[i+1][0]
		}
		if c := strings.Index(strings.ToLower(page[openEnd:spanEnd]), "</form>"); c >= 0 {
			spanEnd = openEnd + c
		}
		fs := map[string]string{}
		for _, tag := range reInputTag.FindAllString(page[openEnd:spanEnd], -1) {
			nm, ok := attrValue(reNameAttr, tag)
			if !ok || nm == "" {
				continue
			}
			val := ""
			if v, ok := attrValue(reValAttr, tag); ok {
				val = html.UnescapeString(v)
			}
			fs[nm] = val
		}
		// The sign-in form is the one holding the credential input. Match on content,
		// not page order, so decoy forms cannot hijack the action.
		if _, hasPass := fs[fieldPassword]; hasPass {
			if v, ok := attrValue(reActAttr, page[loc[0]:loc[1]]); ok {
				action = html.UnescapeString(v)
			}
			return action, fs
		}
	}
	// No form on the page carries a Password input: return nothing rather than blindly
	// adopting some other form's action. checkLoginForm reports this as a page-shape
	// change (FailUnexpected), which keeps sessions and passwords intact.
	return "", fields
}

// attrValue returns an attribute's value and whether the attribute was PRESENT.
// Presence is read from the submatch index rather than from the returned string,
// because value="" is a present-but-empty attribute and the antiforgery check
// turns on exactly that distinction.
func attrValue(re *regexp.Regexp, tag string) (string, bool) {
	loc := re.FindStringSubmatchIndex(tag)
	if loc == nil {
		return "", false
	}
	// Exactly one of the three quoting alternatives participates in a match; the
	// others report -1. A participating group of zero length is a real empty value.
	for g := 1; 2*g+1 < len(loc); g++ {
		if loc[2*g] >= 0 {
			return tag[loc[2*g]:loc[2*g+1]], true
		}
	}
	return "", true
}

// checkLoginForm rejects a harvested form that is not the credential form this
// client knows how to submit, so an unrecognised page shape fails as a page-shape
// problem instead of being submitted blind and coming back as "your password is
// wrong".
func checkLoginForm(fields map[string]string) error {
	// An antiforgery token that is present but EMPTY is as useless as one that is
	// absent: ASP.NET refuses the POST either way. The old presence-only check let
	// that case through, which meant the password was sent and the refusal was then
	// reported to the user as a bad password.
	if tok, ok := fields[fieldAntiforgery]; !ok || tok == "" {
		return fmt.Errorf("%w: no usable %s on the page (present=%v, empty=%v)",
			provider.ErrLoginFormUnrecognised, fieldAntiforgery, ok, tok == "")
	}
	// The credential inputs are filled in by name, so a rename would have us POST
	// the password under a name the server ignores. Their absence is the earliest
	// and clearest evidence that this is not the form we think it is.
	for _, f := range []string{fieldUsername, fieldPassword} {
		if _, ok := fields[f]; !ok {
			return fmt.Errorf("%w: the page has no %q input, so it is not the sign-in form", provider.ErrLoginFormUnrecognised, f)
		}
	}
	return nil
}

// redirectSchemeOK reports whether a login-flow redirect to reqScheme is acceptable
// given wantScheme (the scheme of the configured authorize URL). An https flow must
// never follow a hop to a non-https scheme — even to a configured portal host —
// because that downgrades the login page's URL and, with it, the target the plaintext
// credential POST is resolved against. A flow configured on http (local/dev, or a
// test server) has nothing to downgrade, so http hops are fine there.
func redirectSchemeOK(reqScheme, wantScheme string) bool {
	if strings.EqualFold(wantScheme, "https") {
		return strings.EqualFold(reqScheme, "https")
	}
	return true
}

// resolveAction resolves a possibly-relative form action against the login page
// URL and returns an absolute URL string — but only if it stays on a configured
// portal host and keeps the login page's scheme.
//
// This is the check that stops a plaintext password leaving the server. The login
// HTML is scraped, so its action attribute is portal-controlled: HTML injection
// on the portal's sign-in page (or a stored XSS there) could set an absolute
// action and have this client POST fields["Password"] straight to a third party,
// while the user saw nothing but an ordinary failed login. The scheme is held
// constant for the same reason — an https page pointing its form at http:// would
// put the password on the wire in clear without changing host at all.
//
// The base URL is checked too, not just the resolved one: with a relative action
// the base IS the target, and it is the end of a redirect chain.
func resolveAction(base *url.URL, action string, allowed map[string]bool) (string, error) {
	if !allowed[strings.ToLower(base.Host)] {
		return "", fmt.Errorf("%w: the sign-in page was served from %q, which is not a configured portal host",
			provider.ErrLoginOffHost, safeExcerpt(base.Host))
	}
	if action == "" {
		return base.String(), nil
	}
	ref, err := url.Parse(action)
	if err != nil {
		return "", fmt.Errorf("%w: unparseable form action %q: %v", provider.ErrLoginFormUnrecognised, safeExcerpt(action), err)
	}
	u := base.ResolveReference(ref)
	if !allowed[strings.ToLower(u.Host)] {
		return "", fmt.Errorf("%w: the sign-in page asked us to post credentials to %q, which is not a configured portal host (action %q)",
			provider.ErrLoginOffHost, safeExcerpt(u.Host), safeExcerpt(action))
	}
	if !strings.EqualFold(u.Scheme, base.Scheme) {
		return "", fmt.Errorf("%w: the sign-in page asked us to post credentials over %q from a %q page (action %q)",
			provider.ErrLoginOffHost, safeExcerpt(u.Scheme), base.Scheme, safeExcerpt(action))
	}
	return u.String(), nil
}

// hasCookieNamed reports whether a serialised Cookie header carries a cookie with
// exactly this name and a non-empty value.
//
// A substring test matched the PREFIXED siblings the IDM also sets on the way
// through a login — .External, .Nonce, .Antiforgery — so a login that FAILED but
// left one of those in the jar reported success: a useless cookie was sealed and
// the user's password stored for a session that did not exist. The value must be
// non-empty too, since a name with no value is a cookie the server is clearing.
func hasCookieNamed(header, name string) bool {
	for _, kv := range strings.Split(header, ";") {
		n, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
		if n == name && v != "" {
			return true
		}
	}
	return false
}

// maxPortalExcerpt bounds how much portal-controlled text may appear in an error
// string. The bound is about the log as much as the message: these errors reach
// log.Printf, and without it a broken portal writes up to the full megabyte we
// are willing to read into the journal on every attempt.
const maxPortalExcerpt = 200

// safeExcerpt renders portal-controlled text for an error message: control
// characters replaced with spaces, then truncated. Newlines are the reason this
// exists — an error string carrying one into log.Printf lets whoever controls the
// portal forge log lines, so a hostile response could bury its own traces under
// plausible-looking entries.
func safeExcerpt(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxPortalExcerpt {
		// Truncating by bytes can cut a rune in half; dropping the invalid tail keeps
		// the message printable.
		s = strings.ToValidUTF8(s[:maxPortalExcerpt], "") + "…(truncated)"
	}
	return s
}

// jarCookieHeader serialises the cookies the jar would send to u.
func jarCookieHeader(jar http.CookieJar, u *url.URL) string {
	var parts []string
	for _, ck := range jar.Cookies(u) {
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	return strings.Join(parts, "; ")
}

// mergeSetCookie applies Set-Cookie values from a response onto an existing
// Cookie header, preserving order and returning the updated header. Used to
// carry forward a rotated session cookie after silent-renew.
func mergeSetCookie(existing string, set []*http.Cookie) string {
	if len(set) == 0 {
		return existing
	}
	var order []string
	vals := map[string]string{}
	for _, kv := range strings.Split(existing, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		name, val := kv, ""
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name, val = kv[:i], kv[i+1:]
		}
		if _, seen := vals[name]; !seen {
			order = append(order, name)
		}
		vals[name] = val
	}
	for _, ck := range set {
		// A deletion (Max-Age<0 or an Expires in the past) means the server wants
		// the cookie GONE; keeping "name=" would re-send a credential the IDM
		// meant to clear.
		if ck.MaxAge < 0 || (!ck.Expires.IsZero() && ck.Expires.Before(time.Now())) {
			delete(vals, ck.Name)
			continue
		}
		if _, seen := vals[ck.Name]; !seen {
			order = append(order, ck.Name)
		}
		vals[ck.Name] = ck.Value
	}
	parts := make([]string, 0, len(order))
	for _, name := range order {
		if v, ok := vals[name]; ok {
			parts = append(parts, name+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}
