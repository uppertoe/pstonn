package server

import (
	"net/http"

	"github.com/uppertoe/pstonn/internal/identity"
)

// landing is the PUBLIC marketing page (not behind forward-auth): what the app
// does and how, with a sign-in button. Signed-in visitors get an "Open the app"
// button instead.
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

// about is the PUBLIC page describing the security model and notifications
// frankly (no promises).
func (s *Server) about(w http.ResponseWriter, r *http.Request) {
	_, signedIn := identity.FromContext(r.Context())
	s.render(w, dashboardData{State: "about", SignedIn: signedIn, Contact: s.cfg.ContactEnabled(), Loc: s.cfg.DisplayLocation})
}

// why is the PUBLIC "how it works" page: a plain explainer, the animated demos,
// and how to get set up with a council ePermit.
func (s *Server) why(w http.ResponseWriter, r *http.Request) {
	_, signedIn := identity.FromContext(r.Context())
	s.render(w, dashboardData{State: "why", SignedIn: signedIn, Contact: s.cfg.ContactEnabled(), Loc: s.cfg.DisplayLocation})
}
