// Package webauth implements the app's user login as an OIDC relying party
// against the OIDC provider (Authorization Code + PKCE). On success it issues the signed
// session cookie from internal/session. This is entirely separate from the
// council permit-link flow in internal/parking, which is a different OAuth
// client against a different identity provider.
package webauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/identity"
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
		verifier:    provider.Verifier(&oidc.Config{ClientID: cfg.AppOIDC.ClientID}),
		store:       st,
		sessions:    sessions,
		adminGroups: admin,
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
	if err := a.sessions.Issue(w, u); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("app login: %s", u.Email)
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

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
