// Package webauth implements the app's user login as an OIDC relying party
// against the OIDC provider (Authorization Code + PKCE). On success it issues the signed
// session cookie from internal/session. This is entirely separate from the
// tenant permit-link flow in internal/parking, which is a different OAuth
// client against a different identity provider.
package webauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/session"
	"github.com/uppertoe/pstonn/internal/store"
)

// Authenticator drives the OIDC login.
type Authenticator struct {
	oauth       oauth2.Config
	verifier    *oidc.IDTokenVerifier
	store       *store.Store
	sessions    *session.Manager
	adminGroups map[string]bool
	// cookieSecure mirrors COOKIE_SECURE for the short-lived state cookie below.
	cookieSecure bool
}

// stateCookie carries the authorization request's state value in the browser that
// started the login, so the callback can prove the two are the same browser.
//
// Without it, state is only a server-side record and nothing ties it to a client:
// an attacker can begin a login, authenticate as themselves, capture the resulting
// ?code=&state= without visiting it, and hand that URL to a victim, whose browser
// then completes the exchange and receives a session for the ATTACKER's account.
// The victim notices nothing — and the next thing this app asks a signed-in user
// for is their tenant password, which would be typed into an account they do not
// control.
// stateCookie is the legacy (unprefixed) name, still READ during the rename. When
// cookies are secure the state cookie is written under the __Host- name instead, which
// a browser only honours when it is Secure, Path=/ and Domain-less — the properties
// that stop a sibling subdomain planting a same-named state cookie to seed a login-CSRF.
// The prefix requires Secure and Path=/, so it is used only over HTTPS; the path moves
// from /auth/ to / to satisfy it (the cookie is only read in the callback under /auth/,
// which "/" still covers).
const stateCookie = "pstonn_oauth_state"
const hostStateCookie = "__Host-pstonn_oauth_state"

// stateCookieTTL bounds the login round-trip. It matches the server-side state TTL
// in internal/store, so neither half outlives the other.
const stateCookieTTL = 15 * time.Minute

func (a *Authenticator) stateCookieName() string {
	if a.cookieSecure {
		return hostStateCookie
	}
	return stateCookie
}

func (a *Authenticator) setStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.stateCookieName(),
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cookieSecure,
		// Lax, not Strict: the callback is a top-level navigation FROM the identity
		// provider, which is cross-site. Strict would withhold the cookie there and
		// break every login.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(stateCookieTTL.Seconds()),
	})
}

func (a *Authenticator) clearStateCookie(w http.ResponseWriter) {
	// Expire the name new logins use AND the legacy plain name at its old /auth/ path,
	// so a login STARTED before the __Host- rename (whose cookie was written at
	// Path=/auth/) is still cleared when it completes after the deploy. A cookie is
	// keyed by (name, path), so the legacy one must be expired at the path it was set.
	type ck struct{ name, path string }
	targets := []ck{{a.stateCookieName(), "/"}, {stateCookie, "/auth/"}}
	for _, t := range targets {
		http.SetCookie(w, &http.Cookie{
			Name:     t.name,
			Value:    "",
			Path:     t.path,
			HttpOnly: true,
			Secure:   a.cookieSecure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}
}

// stateMatchesBrowser reports whether the callback's state was issued to THIS
// browser. Constant-time, though the value is 256 bits of crypto/rand so the
// comparison is not the weak link. It accepts EITHER cookie name so a login started
// before the __Host- rename still completes.
func stateMatchesBrowser(r *http.Request, state string) bool {
	if state == "" {
		return false
	}
	c, err := r.Cookie(hostStateCookie)
	if err != nil || c.Value == "" {
		c, err = r.Cookie(stateCookie)
	}
	if err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) == 1
}

// New builds an Authenticator, or returns (nil, nil) if OIDC login is disabled.
func New(ctx context.Context, cfg *config.Config, st *store.Store, sessions *session.Manager) (*Authenticator, error) {
	if !cfg.AppOIDC.Enabled() {
		return nil, nil
	}
	provider, err := oidc.NewProvider(ctx, cfg.AppOIDC.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery (%s): %w", cfg.AppOIDC.Issuer, err)
	}
	admin := make(map[string]bool, len(cfg.AppOIDC.AdminGroups))
	for _, g := range cfg.AppOIDC.AdminGroups {
		admin[g] = true
	}
	return &Authenticator{
		oauth: oauth2.Config{
			ClientID:     cfg.AppOIDC.ClientID,
			ClientSecret: cfg.AppOIDC.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.AppOIDC.RedirectURI,
			Scopes:       cfg.AppOIDC.Scopes,
		},
		verifier:     provider.Verifier(&oidc.Config{ClientID: cfg.AppOIDC.ClientID}),
		store:        st,
		sessions:     sessions,
		adminGroups:  admin,
		cookieSecure: cfg.CookieSecure,
	}, nil
}

// Login starts the auth-code+PKCE flow by redirecting to the OIDC provider.
func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request) {
	state, err := randToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	verifier, err := randToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := a.store.PutOAuthState(r.Context(), state, verifier, nonce, "app"); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Bind this authorization request to this browser before redirecting; the
	// callback refuses a state it did not hand out here.
	a.setStateCookie(w, state)
	challenge := s256(verifier)
	url := a.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

// Callback completes the flow: validates state, exchanges the code, verifies the
// ID token (signature + nonce), and issues the session cookie.
func (a *Authenticator) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		http.Error(w, "login failed: "+errParam, http.StatusUnauthorized)
		return
	}
	// The state must be one WE issued (the server-side record, single-use) AND one
	// issued to THIS browser (the cookie). The second half is what stops an attacker
	// completing their own login in someone else's browser; check it first so a
	// replayed callback cannot even consume the stored state.
	if !stateMatchesBrowser(r, q.Get("state")) {
		a.clearStateCookie(w)
		http.Error(w, "this sign-in link was not started in this browser; please sign in again", http.StatusBadRequest)
		return
	}
	a.clearStateCookie(w)
	st, err := a.store.TakeOAuthState(r.Context(), q.Get("state"))
	if err != nil || st.Kind != "app" {
		http.Error(w, "invalid or expired login state", http.StatusBadRequest)
		return
	}
	token, err := a.oauth.Exchange(r.Context(), q.Get("code"),
		oauth2.SetAuthURLParam("code_verifier", st.Verifier))
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusUnauthorized)
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusUnauthorized)
		return
	}
	idToken, err := a.verifier.Verify(r.Context(), rawID)
	if err != nil {
		http.Error(w, "id_token verification failed", http.StatusUnauthorized)
		return
	}
	if idToken.Nonce != st.Nonce {
		http.Error(w, "nonce mismatch", http.StatusUnauthorized)
		return
	}
	var claims struct {
		Email             string   `json:"email"`
		EmailVerified     *bool    `json:"email_verified"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "cannot read claims", http.StatusUnauthorized)
		return
	}

	u := identity.User{
		Email:  lower(claims.Email),
		Name:   firstNonEmpty(claims.Name, claims.PreferredUsername, claims.Email),
		Groups: a.deriveGroups(claims.Groups),
	}
	if u.Email == "" {
		http.Error(w, "no email claim; ensure the 'email' scope is granted", http.StatusUnauthorized)
		return
	}
	// The email IS the account key here — every permit, vehicle and tenant session is
	// scoped by it, and invites are addressed to it. An unverified (or provider-mutable)
	// address therefore means account takeover: sign up as someone else's address at a
	// provider that does not verify, and you land inside their account. Accept only an
	// explicitly verified claim; a provider that omits email_verified is refused rather
	// than trusted, since silence is not a guarantee.
	if claims.EmailVerified == nil || !*claims.EmailVerified {
		log.Printf("oidc: refusing sign-in for %q: email_verified is %v (the email is the account key, so it must be verified)",
			redact.Email(u.Email), claims.EmailVerified)
		http.Error(w, "your identity provider did not confirm this email address is verified, so sign-in was refused", http.StatusUnauthorized)
		return
	}
	if err := a.sessions.Issue(w, u); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("app login: %s", redact.Email(u.Email))
	http.Redirect(w, r, "/", http.StatusFound)
}

// Logout clears the session cookie.
func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request) {
	a.sessions.Clear(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// deriveGroups always grants "user" and adds "admin" when the OIDC groups
// intersect the configured admin groups, so identity.User.IsAdmin works.
func (a *Authenticator) deriveGroups(oidcGroups []string) []string {
	groups := []string{"user"}
	for _, g := range oidcGroups {
		if a.adminGroups[g] {
			groups = append(groups, "admin")
			break
		}
	}
	return groups
}

func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// lower normalises an email claim the SAME way every other path in the app does:
// strings.ToLower over strings.TrimSpace. It used to be a hand-rolled ASCII-only
// fold with no trimming, which meant a provider claim carrying stray whitespace, or
// a non-ASCII uppercase character, produced a session email that could never match
// the row written by an invite — silently voiding a share, with nothing to show why.
// Email is the account key here, so exactly one spelling rule can exist.
func lower(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
