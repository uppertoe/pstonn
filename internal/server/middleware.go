package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/redact"
)

// newScriptNonce mints the per-response CSP script nonce. 16 bytes is well past
// guessable, and it MUST be fresh per response: a fixed or reused nonce is worse
// than none, because it reads as containment while an injected <script
// nonce="…"> would execute. crypto/rand.Read cannot fail without the OS entropy
// source failing, in which case it panics rather than returning short — so there
// is no degraded-nonce path to get wrong here.
//
// URL-safe base64 (the CSP grammar accepts it) so the alphabet is limited to
// characters html/template leaves alone: standard base64's '+' and '=' come back
// out of a template as &#43; and &#61;, which a browser does decode, but it means
// the header and the markup no longer match byte for byte and every test and
// bug-report grep has to know that.
func newScriptNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// cspFor builds the policy for one response around that response's script nonce.
//
// 'unsafe-inline' is deliberately absent from script-src, and adding it back would
// achieve nothing: under CSP3 a nonce in script-src makes browsers IGNORE
// 'unsafe-inline' entirely. Every inline <script> in layout.html carries
// {{.Nonce}} instead, and there are no on* handler attributes anywhere in the
// templates (a nonce cannot cover those, so they were converted to
// addEventListener) — templates_csp_test.go holds both facts.
//
// 'unsafe-eval' MUST STAY. Alpine compiles every x-data / @click / x-show
// expression with `new Function`, and this app leans on Alpine throughout, so
// removing it takes the app apart on the first interaction. Dropping it means
// moving to the @alpinejs/csp build and rewriting each x-data into a registered
// component — a real project, not a tidy-up. Do not "clean this up".
//
// style-src keeps 'unsafe-inline' for the same reason it cannot be nonced: the
// colour language is carried by inline style= attributes (--hue, plate colours)
// on ~20 elements, and nonces apply to elements, not attributes.
//
// object-src is spelled out rather than left to the default-src fallback: it costs
// nothing and it is the one directive whose absence people reach for when they want
// to argue the policy is incomplete.
func cspFor(nonce string) string {
	return "default-src 'self'; " +
		"script-src 'self' 'nonce-" + nonce + "' 'unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
		"object-src 'none'; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
}

// scriptNonce recovers the nonce securityHeaders minted for this response, by
// reading back the CSP header it already set.
//
// The header is the single source of truth on purpose. render() is handed only a
// ResponseWriter and a view model — the request (and so any context value) is out
// of reach, and its ~40 call sites are spread across handler files, so a
// context-threaded nonce would mean changing all of them and would still allow the
// header and the markup to drift apart. Reading it back cannot drift: if the
// attribute is present, it came from the policy actually being enforced.
//
// Absent header returns "", which is the correct answer for a response rendered
// without securityHeaders in front of it (unit tests execute templates directly):
// no policy is being enforced, so there is no nonce to honour.
func scriptNonce(w http.ResponseWriter) string {
	const marker = "'nonce-"
	v := w.Header().Get("Content-Security-Policy")
	i := strings.Index(v, marker)
	if i < 0 {
		return ""
	}
	v = v[i+len(marker):]
	j := strings.IndexByte(v, '\'')
	if j < 0 {
		return ""
	}
	return v[:j]
}

// securityHeaders sets defensive response headers on every request. The CSP
// keeps all resource loads and form posts same-origin (blocking exfiltration and
// external form hijack) and forbids framing (clickjacking); see cspFor for what
// each script-src source is doing there.
func securityHeaders(next http.Handler) http.Handler {
	// The app asks for exactly one powerful feature — the screen wake lock, so a QR
	// stays readable while a visitor holds up their phone. Naming it and denying the
	// rest means a future dependency cannot quietly start using the camera or location.
	const permissions = "screen-wake-lock=(self), camera=(), microphone=(), geolocation=(), " +
		"payment=(), usb=(), serial=(), midi=()"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", cspFor(newScriptNonce()))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", permissions)
		// HSTS only when the request actually arrived over TLS. The site is DNS-only, so
		// no proxy adds this for us — but sending it on a plaintext request is both
		// meaningless (browsers ignore it) and a footgun for a local http run, which
		// would pin localhost to https for the max-age.
		if requestScheme(r) == "https" {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// maxFormBytes caps a request body before anything parses it. Every form in this
// app is a handful of short fields (plates, emails, a contact message capped at
// 4000 chars), so 64 KB is generous. Without a cap, r.FormValue on a
// multipart/form-data body calls ParseMultipartForm, which buffers 32 MB in
// memory AND spills the remainder to temp files — reachable on the public guest
// endpoints, whose tokens are printed on posters in the street.
const maxFormBytes = 64 << 10

// limitBody caps the request body. On overflow the subsequent ParseForm fails
// and the handler's own "could not read the form" path renders, so no caller
// needs to change.
func limitBody(r *http.Request) {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(nil, r.Body, maxFormBytes)
	}
}

// staticSub serves the embedded assets rooted at the static/ directory.
var staticSub = mustSub(staticFS, "static")

func mustSub(f fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

// cacheStatic marks vendored assets cacheable long-term (they are versioned by
// the release image, so immutable within a deploy).
func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		h.ServeHTTP(w, r)
	})
}

// noStoreCache marks a response uncacheable. Every signed-in page shows household
// data — permits, plates, the activity log, who has access — and none of it carried
// any cache directive, so a browser was free to keep it: on the shared family device
// this app is explicitly built for, one person signs out and the next presses Back
// and reads the previous person's dashboard out of the back-forward cache.
//
// Deliberately NOT the guest routes' noStore helper, which also sets
// Referrer-Policy: no-referrer. That is right for a page whose URL contains a live
// token, but on an app page it would strip the same-origin Referer that sameOrigin
// falls back on when a request carries no Origin — weakening the CSRF check to fix a
// caching bug. Pragma is for the HTTP/1.0 intermediaries that ignore Cache-Control.
func noStoreCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
}

// misconfigAlertEvery throttles the misconfigured-route operator alert. A broken
// route floods this branch on every attempt; one page per window is enough.
const misconfigAlertEvery = 15 * time.Minute

// alertMisconfiguredRoute pages the operator that a signed-in-only route is
// reachable without identity — an app route missing from the reverse proxy's
// forward-auth list, or a proxy-secret mismatch. Throttled; a no-op when no
// admin channel is configured (local/dev).
func (s *Server) alertMisconfiguredRoute(method, path string) {
	if s.notify == nil || !s.notify.AdminConfigured() {
		return
	}
	now := time.Now().UnixNano()
	prev := s.misconfigAlertAt.Load()
	if now-prev < int64(misconfigAlertEvery) || !s.misconfigAlertAt.CompareAndSwap(prev, now) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = s.notify.NotifyAdmin(ctx,
			"Sign-in BROKEN for a route — check the proxy config",
			fmt.Sprintf("A signed-in-only route (%s %s) was reached WITHOUT an identity behind forward-auth. In a correct deployment this cannot happen: either this route is missing from the reverse proxy's forward-auth path list (so it fell through to the catch-all and no Remote-* headers were injected), or PROXY_SECRET/PSTONN_PROXY_SECRET drifted. Real users cannot get past this route until it is fixed. Add the route to the proxy's @app list (or realign the shared secret), then re-render and redeploy.", method, path))
	}()
}

// user returns the signed-in identity, or redirects/errs and reports ok=false.
func (s *Server) user(w http.ResponseWriter, r *http.Request) (identity.User, bool) {
	if u, ok := identity.FromContext(r.Context()); ok {
		return u, true
	}
	if s.auth != nil {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
	} else {
		// A visitor sees a plain apology; the operator jargon (which env vars are
		// missing) goes to the log where it belongs. This state means the deployment
		// is misconfigured, so it is the operator who needs the detail, not a member
		// of the public reading about APP_OIDC_*.
		// Behind forward-auth (the production posture), reaching a signed-in-only
		// handler with NO identity is impossible in a correct deployment: the proxy
		// either injects the verified Remote-* headers or redirects an anonymous
		// visitor to the login page. If we are here, a real route is missing from
		// the proxy's forward-auth path (so it fell to the catch-all, which injects
		// no identity), or the shared proxy secret drifted — either way legitimate
		// sign-in is broken for that route and no user can get past it. That is an
		// operator emergency, and it used to be only a log line nobody watched (it
		// hid a two-day /tenant/link outage). Page the operator, throttled, naming
		// the route so the fix is obvious. Not fired in local/dev (no admin channel).
		log.Printf("sign-in is not configured for %s %s: run behind the forward-auth layer, set APP_OIDC_*, or use DEV_IDENTITY_EMAIL for local use", r.Method, r.URL.Path)
		s.alertMisconfiguredRoute(r.Method, r.URL.Path)
		s.message(w, http.StatusUnauthorized, "Sign-in isn't available right now. Please try again shortly.")
	}
	return identity.User{}, false
}

// resolveAccount resolves which account the signed-in user acts within.
//   - user is the raw signed-in email (used for per-user consent and for audit).
//   - owner is the email that scopes all shared account data: the user's own
//     when they run their own account, or the primary they are a secondary of.
//   - isPrimary is false when the user is a secondary (a guest on someone's
//     account), which gates the owner-only actions (tenant link/unlink, account
//     delete, managing members).
func (s *Server) resolveAccount(ctx context.Context) (user, owner string, isPrimary bool) {
	user, owner, isPrimary, err := s.resolveAccountStrict(ctx)
	if err != nil {
		// READ-path fallback: the caller's OWN account, primary privilege withheld —
		// a DB blip costs a 403 on owner-only gates, not a privilege. Harmless for a
		// read (a secondary just sees their own empty account for a moment). A MUTATING
		// handler must NOT use this: it would write into that phantom own-account. Those
		// use resolveAccountStrict and fail closed — see its doc.
		log.Printf("resolveAccount %s: membership lookup failed (own account, primary privilege withheld): %v", redact.Email(user), err)
		return user, user, false
	}
	return user, owner, isPrimary
}

// resolveAccountStrict is resolveAccount but surfaces a membership-lookup failure, so
// a MUTATING handler can fail CLOSED (503, write nothing) instead of silently writing
// into a secondary's own phantom account when we cannot establish their scope. For
// authorization scoping, "cannot determine" must mean "perform no mutation".
func (s *Server) resolveAccountStrict(ctx context.Context) (user, owner string, isPrimary bool, err error) {
	u, _ := identity.FromContext(ctx)
	user = u.Email
	primary, ok, err := s.store.MemberAccount(ctx, user)
	if err != nil {
		return user, "", false, err
	}
	if ok && primary != "" {
		return user, primary, false, nil
	}
	return user, user, true, nil
}

// accountForWrite resolves the acting account for a MUTATING handler, writing a 503
// and returning ok=false if the account scope cannot be established (so the caller
// returns without mutating). Centralises the fail-closed response.
func (s *Server) accountForWrite(w http.ResponseWriter, r *http.Request) (user, owner string, isPrimary, ok bool) {
	user, owner, isPrimary, err := s.resolveAccountStrict(r.Context())
	if err != nil {
		log.Printf("accountForWrite %s: membership lookup failed; refusing the mutation: %v", redact.Email(user), err)
		s.message(w, http.StatusServiceUnavailable, "We couldn't confirm your account just now. Please try again in a moment.")
		return "", "", false, false
	}
	return user, owner, isPrimary, true
}

func (s *Server) withUser(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.user(w, r)
		if !ok {
			return
		}
		noStoreCache(w)
		// CSRF: every authenticated mutation must come from our own origin. This
		// wraps all mutating routes (withConsent calls withUser), so a cross-site
		// POST can't trigger link/unlink/delete/schedule changes.
		//
		// Checked BEFORE touchActivity: a request we are about to reject must not
		// have side effects, and resetting the idle clock is one — it extends how
		// long a tenant session is held for a household that may have left.
		if isStateChanging(r) && !sameOrigin(r) {
			s.message(w, http.StatusForbidden, "This request could not be verified. Please reload the page and try again.")
			return
		}
		// Being here resets the account's idle clock (see decideWarm): the
		// re-authorise bound exists to stop holding a tenant session for a household
		// that has left, and someone signed in and using the app has not left.
		s.touchActivity(r.Context(), u.Email)
		if isStateChanging(r) {
			limitBody(r)
		}
		h(w, r)
	}
}

// withConsent is withUser plus a terms-acceptance gate, used for every action
// that stores or changes user data (so nothing happens, and no tenant login is
// stored, before the user has accepted the current terms).
func (s *Server) withConsent(h http.HandlerFunc) http.HandlerFunc {
	return s.withUser(func(w http.ResponseWriter, r *http.Request) {
		u, _ := identity.FromContext(r.Context())
		if ok, _ := s.consentStatus(r.Context(), u.Email); !ok {
			redirectHome(w, r) // schedule handler re-renders the terms gate
			return
		}
		h(w, r)
	})
}

func (s *Server) requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.user(w, r)
		if !ok {
			return
		}
		if !u.IsAdmin() {
			s.message(w, http.StatusForbidden, "This action is limited to administrators.")
			return
		}
		// The admin page lists every account's email and push topic, so it is the last
		// page that should sit in a shared browser's history cache.
		noStoreCache(w)
		h(w, r)
	}
}
