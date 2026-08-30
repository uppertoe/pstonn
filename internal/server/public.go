package server

import (
	"net/http"

	"github.com/uppertoe/pstonn/internal/identity"
)

// landing is the PUBLIC marketing page (not behind forward-auth): what the app
// does and how, with a sign-in button. Signed-in visitors get an "Open the app"
// button instead.
// signin is the target of every public "Sign in" button. Behind forward-auth
// the request only arrives once the person is signed in, so it forwards to the
// app; under the app's own OIDC login it starts that flow; with neither (a
// misconfigured deployment) it falls back to the landing page rather than a
// dead end.
func (s *Server) signin(w http.ResponseWriter, r *http.Request) {
	if _, ok := identity.FromContext(r.Context()); ok {
		http.Redirect(w, r, "/schedule", http.StatusFound)
		return
	}
	if s.auth != nil {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) landing(w http.ResponseWriter, r *http.Request) {
	_, signedIn := identity.FromContext(r.Context())
	// A signed-in visitor goes straight to the app rather than the marketing page.
	// In production the auth layer already makes this call at the edge (see
	// deploy/pstonn.caddy) and a signed-in user never reaches here; this covers the
	// local/dev run (no forward-auth) and any deployment that does pass identity.
	if signedIn {
		http.Redirect(w, r, "/schedule", http.StatusSeeOther)
		return
	}
	s.render(w, dashboardData{
		State: "landing", OIDCEnabled: s.auth != nil, LogoutURL: s.logoutURL(),
		SignedIn: signedIn, Contact: s.cfg.ContactEnabled(), Loc: s.cfg.DisplayLocation,
	})
}

// security is the PUBLIC page describing how the tenant login is held, what
// else is stored, and what is not promised. Named for what it contains: it is a
// security and data page, and filing it under "about" hid the one thing a visitor
// most wants before handing over a tenant password.
func (s *Server) security(w http.ResponseWriter, r *http.Request) {
	_, signedIn := identity.FromContext(r.Context())
	s.render(w, dashboardData{State: "security", SignedIn: signedIn, Contact: s.cfg.ContactEnabled(), Loc: s.cfg.DisplayLocation})
}

// how is the PUBLIC "how it works" page: why the app exists, the animated demos,
// and what you need before starting.
func (s *Server) how(w http.ResponseWriter, r *http.Request) {
	_, signedIn := identity.FromContext(r.Context())
	s.render(w, dashboardData{State: "how", SignedIn: signedIn, Contact: s.cfg.ContactEnabled(), Loc: s.cfg.DisplayLocation})
}
