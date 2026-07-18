// Package identity resolves the authenticated user from the trusted headers
// injected by the platform's Caddy forward_auth layer. This app implements no
// login of its own: Caddy authenticates the request against vps-scaffold-auth,
// strips any client-supplied identity headers, and re-injects the authoritative
// values Remote-User / Remote-Email / Remote-Groups before proxying to us.
//
// See vps-scaffold conventions: header names are Remote-* (not X-Auth-*), and
// Groups is a comma-separated list containing "admin" and/or "user".
package identity

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey struct{}

// User is the resolved identity for a request.
type User struct {
	Email  string
	Name   string
	Groups []string
}

// IsAdmin reports whether the user is in the admin group.
func (u User) IsAdmin() bool {
	for _, g := range u.Groups {
		if g == "admin" {
			return true
		}
	}
	return false
}

// Decoder resolves a User from a request (e.g. from the app's signed session
// cookie). It reports ok=false when no valid identity is present.
type Decoder func(*http.Request) (User, bool)

// Middleware resolves the request identity.
//
// trustForwardAuth MUST be true only when the app runs behind the platform's
// forward_auth layer (its own OIDC login disabled). In that mode the Remote-*
// headers are authoritative (Caddy strips any client-supplied copies and
// re-injects the verified values). When the app runs its OWN OIDC login instead,
// trustForwardAuth is false and Remote-* headers are ignored entirely, so an
// attacker cannot present a Remote-Email header to override the verified session
// cookie.
//
// Precedence: (1) Remote-* headers when trustForwardAuth; (2) the app's signed
// session cookie via decode (OIDC login); (3) devEmail, a local/standalone
// fallback that MUST be empty in production. decode may be nil.
func Middleware(devEmail string, decode Decoder, trustForwardAuth bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var u User
			if trustForwardAuth {
				if email := strings.ToLower(strings.TrimSpace(r.Header.Get("Remote-Email"))); email != "" {
					u = User{
						Email:  email,
						Name:   strings.TrimSpace(r.Header.Get("Remote-User")),
						Groups: splitGroups(r.Header.Get("Remote-Groups")),
					}
				}
			}
			if u.Email == "" && decode != nil {
				if du, ok := decode(r); ok {
					u = du
				}
			}
			if u.Email == "" && devEmail != "" {
				u = User{Email: devEmail, Name: devEmail, Groups: []string{"user", "admin"}}
			}
			ctx := context.WithValue(r.Context(), ctxKey{}, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromContext returns the resolved user and whether one was present.
func FromContext(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(ctxKey{}).(User)
	return u, ok && u.Email != ""
}

// RequireUser wraps a handler so it only runs for an authenticated request.
// Behind the platform this is belt-and-braces (Caddy already gates the route),
// but it also protects standalone runs and makes the dependency explicit.
func RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := FromContext(r.Context()); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func splitGroups(raw string) []string {
	var out []string
	for _, g := range strings.Split(raw, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}
