package server

import (
	"context"
	"io/fs"
	"log"
	"net/http"

	"github.com/uppertoe/pstonn/internal/identity"
)

// securityHeaders sets defensive response headers on every request. The CSP
// keeps all resource loads and form posts same-origin (blocking exfiltration and
// external form hijack) and forbids framing (clickjacking). Alpine needs
// 'unsafe-eval' and the few inline <script>/style blocks need 'unsafe-inline';
// everything else is locked to 'self'.
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
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
		log.Print("sign-in is not configured: run behind the forward-auth layer, set APP_OIDC_*, or use DEV_IDENTITY_EMAIL for local use")
		s.message(w, http.StatusUnauthorized, "Sign-in isn't available right now. Please try again shortly.")
	}
	return identity.User{}, false
}

// resolveAccount resolves which account the signed-in user acts within.
//   - user is the raw signed-in email (used for per-user consent and for audit).
//   - owner is the email that scopes all shared account data: the user's own
//     when they run their own account, or the primary they are a secondary of.
//   - isPrimary is false when the user is a secondary (a guest on someone's
//     account), which gates the owner-only actions (council link/unlink, account
//     delete, managing members).
func (s *Server) resolveAccount(ctx context.Context) (user, owner string, isPrimary bool) {
	u, _ := identity.FromContext(ctx)
	user = u.Email
	primary, ok, err := s.store.MemberAccount(ctx, user)
	if err != nil {
		// Data access still resolves to the caller's OWN account (so this can never
		// read anyone else's data), but we no longer grant primary privilege on a
		// failed lookup: if we can't prove they aren't a secondary, deny the
		// owner-only gates (council link/unlink, account delete, member management)
		// rather than fail open. A DB blip should cost a 403, not a privilege.
		log.Printf("resolveAccount %s: membership lookup failed (own account, primary privilege withheld): %v", user, err)
		return user, user, false
	}
	if ok && primary != "" {
		return user, primary, false
	}
	return user, user, true
}

func (s *Server) withUser(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.user(w, r); !ok {
			return
		}
		// CSRF: every authenticated mutation must come from our own origin. This
		// wraps all mutating routes (withConsent calls withUser), so a cross-site
		// POST can't trigger link/unlink/delete/schedule changes.
		if isStateChanging(r) && !sameOrigin(r) {
			s.message(w, http.StatusForbidden, "This request could not be verified. Please reload the page and try again.")
			return
		}
		if isStateChanging(r) {
			limitBody(r)
		}
		h(w, r)
	}
}

// withConsent is withUser plus a terms-acceptance gate, used for every action
// that stores or changes user data (so nothing happens, and no council login is
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
		h(w, r)
	}
}
