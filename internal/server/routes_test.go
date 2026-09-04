package server

import (
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/config"
)

// TestHandlerRoutesNoConflict registers every route, so a Go 1.22 ServeMux
// pattern conflict (which panics at registration) is caught by unit tests, not
// only the CI boot smoke test. A minimal cfg lets Handler() finish past its
// post-registration middleware setup.
func TestHandlerRoutesNoConflict(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("route registration panicked (pattern conflict?): %v", r)
		}
	}()
	_ = (&Server{cfg: &config.Config{}}).Handler()
}

// isMutatingPattern reports whether a "METHOD /path" registration is state-changing.
func isMutatingPattern(methodPattern string) bool {
	for _, m := range []string{"POST ", "PUT ", "PATCH ", "DELETE "} {
		if strings.HasPrefix(methodPattern, m) {
			return true
		}
	}
	return false
}

// TestMutatingRoutesAreGuarded is the derived replacement for eyeballing Handler:
// every state-changing route must sit behind withConsent (auth + CSRF + consent) —
// the safe default — unless it is a deliberately consent-exempt user mutation or a
// token/signature-authenticated public one, each of which is enumerated here with
// its reason. A new mutating route registered with the wrong guard (guardUser or
// guardPublic without being listed, or guardAdmin — requireAdmin runs no CSRF
// check) fails this test instead of silently shipping ungated. This is the
// invariant the hand-kept probe lists in authz_test.go could not guarantee.
func TestMutatingRoutesAreGuarded(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	_ = s.Handler()
	if len(s.routes) == 0 {
		t.Fatal("Handler recorded no routes")
	}

	// guardUser mutations: signed-in + CSRF, but consent-exempt on purpose.
	userMutations := map[string]string{
		"POST /terms/accept":           "accepting the terms cannot itself require prior consent",
		"POST /terms/decline":          "declining the terms cannot require prior consent",
		"POST /account/invite/accept":  "answering an invite precedes any consent",
		"POST /account/invite/decline": "declining an invite must not require agreeing to terms",
		"POST /tenant/unlink":          "leaving must not require re-consent",
		"POST /tenant/forget-password": "housekeeping a departing user must not require re-consent",
		"POST /account/delete":         "deleting the account must not require re-consent",
		"POST /account/leave":          "a secondary can always leave",
	}
	// guardPublic mutations: authenticated by a signed token or a request signature,
	// so CSRF-exempt by design (many are cross-origin one-click POSTs from email/apps).
	publicMutations := map[string]string{
		"POST /contact":               "public contact form; its own per-IP rate limit",
		"POST /ntfy/confirm/{token}":  "ntfy app one-tap confirm; token-authenticated",
		"POST /tenant/confirm":        "renewal-confirm link; single-use token",
		"POST /council/confirm":       "renewal-confirm link (legacy path); single-use token",
		"POST /u/{addr}/{token}":      "RFC 8058 one-click unsubscribe; signed token",
		"POST /r/{id}/{addr}/{token}": "no-sign-in guest decide link; signed token",
		"POST /hooks/ses":             "SES/SNS bounce webhook; message signature",
		"POST /g/{token}":             "guest-pass activation; possession of the link is the grant",
		"POST /g/{token}/revert":      "guest-pass revert; same token",
	}

	for _, rt := range s.routes {
		if !isMutatingPattern(rt.methodPattern) {
			continue
		}
		safe := false
		switch rt.guard {
		case guardConsent:
			safe = true
		case guardUser:
			_, safe = userMutations[rt.methodPattern]
		case guardPublic:
			_, safe = publicMutations[rt.methodPattern]
		case guardAdmin:
			safe = false // requireAdmin runs no CSRF check; there is no admin mutation today
		}
		if !safe {
			t.Errorf("mutating route %q has guard %d but is not an approved guarded mutation: "+
				"register it with guardConsent, or justify it in userMutations/publicMutations",
				rt.methodPattern, rt.guard)
		}
	}
}
