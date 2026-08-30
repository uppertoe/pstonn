package server

import (
	"net/http"
	"strings"
	"testing"
)

// The landing page's Sign in button must always lead somewhere that starts a
// sign-in, never back to the landing page. It linked to /schedule until the edge
// began sending anonymous /schedule to the landing page (shared-link hygiene),
// which looped every sign-in for two days (2026-08-28..30). /signin exists so
// that the button's target is a path with exactly one job.
func TestSigninRouteForwardsSignedInAndFallsBackAnonymous(t *testing.T) {
	s := newAuthzServer(t)

	rec := s.doReq(http.MethodGet, "/signin", "owner@example.com", "", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/schedule" {
		t.Fatalf("signed in: got %d -> %q, want 302 -> /schedule", rec.Code, rec.Header().Get("Location"))
	}

	// Forward-auth mode with no identity (the edge would normally have prompted
	// first): no OIDC to start, so land on the public page rather than a dead end.
	rec = s.doReq(http.MethodGet, "/signin", "", "", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("anonymous: got %d -> %q, want 302 -> /", rec.Code, rec.Header().Get("Location"))
	}
}

// Every public sign-in control points at /signin for an anonymous visitor and at
// the app for a signed-in one.
func TestPublicSignInLinksTargetSignin(t *testing.T) {
	s := newAuthzServer(t)
	anon := s.doReq(http.MethodGet, "/", "", "", nil)
	if anon.Code != http.StatusOK {
		t.Fatalf("landing anonymous: %d", anon.Code)
	}
	body := anon.Body.String()
	if !strings.Contains(body, `href="/signin"`) {
		t.Fatal("anonymous landing has no /signin link")
	}
	if strings.Contains(body, `<a href="/schedule" hx-boost="false">`) {
		t.Fatal("anonymous landing still links its sign-in button to /schedule")
	}
}
