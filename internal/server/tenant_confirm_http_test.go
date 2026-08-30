package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// The renewal-confirm link is the one public, unauthenticated route that
// EXTENDS how long a tenant session is held, so its guards are worth locking at
// the HTTP level: the GET must not act, the POST must be throttled and
// body-capped, a used or aged-out token must land on the "nothing to do" page,
// and the /council/confirm alias must behave identically to /tenant/confirm.

// confirmDo drives the route through the real router from a public peer.
func (s *Server) confirmDo(method, path, ip string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "app.example.com"
	r.RemoteAddr = ip + ":40000"
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// seedConfirmToken links an account and marks its reminder as sent with token.
func seedConfirmToken(t *testing.T, s *Server, owner, token string) {
	t.Helper()
	ctx := context.Background()
	if err := s.store.SaveTenantSession(ctx, store.TenantSession{Owner: owner}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.MarkReminderSent(ctx, owner, "", token); err != nil {
		t.Fatal(err)
	}
}

func TestTenantConfirmOverHTTP(t *testing.T) {
	const owner = "quiet@example.com"
	const askCopy = "Keep your permit scheduler running?"
	const doneCopy = "keep running"
	const staleCopy = "Nothing to do here"

	for _, path := range []string{"/tenant/confirm", "/council/confirm"} {
		t.Run(path, func(t *testing.T) {
			s := newAuthzServer(t)
			seedConfirmToken(t, s, owner, "tok-live")

			// GET renders the button and consumes nothing: a mail scanner following
			// the link must not be able to satisfy the liveness check.
			get := s.confirmDo(http.MethodGet, path+"?token=tok-live", "203.0.113.1", "")
			if get.Code != 200 || !strings.Contains(get.Body.String(), askCopy) || !strings.Contains(get.Body.String(), `value="tok-live"`) {
				t.Fatalf("GET = %d %s", get.Code, excerpt(get.Body.String()))
			}
			if get.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("GET Cache-Control = %q, want no-store (the URL carries the token)", get.Header().Get("Cache-Control"))
			}
			cs, err := s.store.GetTenantSession(context.Background(), owner)
			if err != nil || cs.ConfirmToken == "" {
				t.Fatalf("GET consumed the token: %+v %v", cs, err)
			}
			// No token at all renders the stale page straight away.
			if bare := s.confirmDo(http.MethodGet, path, "203.0.113.1", ""); !strings.Contains(bare.Body.String(), staleCopy) {
				t.Fatalf("GET without token = %s", excerpt(bare.Body.String()))
			}

			// The POST acts, once.
			post := s.confirmDo(http.MethodPost, path, "203.0.113.1", url.Values{"token": {"tok-live"}}.Encode())
			if post.Code != 200 || !strings.Contains(post.Body.String(), doneCopy) {
				t.Fatalf("POST = %d %s", post.Code, excerpt(post.Body.String()))
			}
			cs, err = s.store.GetTenantSession(context.Background(), owner)
			if err != nil || cs.ConfirmToken != "" || !cs.ReminderSent.IsZero() {
				t.Fatalf("POST did not consume the token/reminder: %+v %v", cs, err)
			}
			again := s.confirmDo(http.MethodPost, path, "203.0.113.1", url.Values{"token": {"tok-live"}}.Encode())
			if again.Code != 200 || !strings.Contains(again.Body.String(), staleCopy) {
				t.Fatalf("second POST = %d %s, want the stale page", again.Code, excerpt(again.Body.String()))
			}
		})
	}
}

// An unknown token is indistinguishable from a used one: the same reassuring
// page, 200, no oracle.
func TestTenantConfirmUnknownTokenIsStale(t *testing.T) {
	s := newAuthzServer(t)
	w := s.confirmDo(http.MethodPost, "/tenant/confirm", "203.0.113.2", url.Values{"token": {"never-issued"}}.Encode())
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Nothing to do here") {
		t.Fatalf("unknown token = %d %s", w.Code, excerpt(w.Body.String()))
	}
}

// A token past its TTL must not extend the session. The bound is the reminder
// lead plus a fortnight (confirmTokenTTL); the store's sweep is what ages a
// token out between reminders, so it stands in for the clock here.
func TestTenantConfirmTTL(t *testing.T) {
	s := newAuthzServer(t)
	const owner = "late@example.com"
	seedConfirmToken(t, s, owner, "tok-old")

	if got, want := s.confirmTokenTTL(), 7*24*time.Hour+14*24*time.Hour; got != want {
		t.Fatalf("default confirmTokenTTL = %v, want %v (lead 7d + 14d)", got, want)
	}
	s.cfg.Council.ReminderLead = 3 * 24 * time.Hour
	if got, want := s.confirmTokenTTL(), 17*24*time.Hour; got != want {
		t.Fatalf("confirmTokenTTL with a 3d lead = %v, want %v", got, want)
	}

	// Age the token out (the periodic sweep, run "in the future").
	if n, err := s.store.ClearStaleConfirmTokens(context.Background(), time.Now().Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("sweep cleared %d (%v), want 1", n, err)
	}
	w := s.confirmDo(http.MethodPost, "/tenant/confirm", "203.0.113.3", url.Values{"token": {"tok-old"}}.Encode())
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Nothing to do here") {
		t.Fatalf("aged-out token = %d %s", w.Code, excerpt(w.Body.String()))
	}
	cs, err := s.store.GetTenantSession(context.Background(), owner)
	if err != nil || cs.ReminderSent.IsZero() {
		t.Fatalf("an aged-out token extended the session: %+v %v", cs, err)
	}
}

// The POST is throttled per IP and says so with Retry-After; the GET is not
// (it only renders). A throttled attempt consumes nothing.
func TestTenantConfirmThrottle(t *testing.T) {
	s := newAuthzServer(t)
	s.confirmLimit = newRateLimiter(2, time.Minute)
	seedConfirmToken(t, s, "busy@example.com", "tok-throttle")

	body := url.Values{"token": {"nope"}}.Encode()
	for i := 0; i < 2; i++ {
		if w := s.confirmDo(http.MethodPost, "/tenant/confirm", "203.0.113.4", body); w.Code != 200 {
			t.Fatalf("attempt %d = %d, want 200", i+1, w.Code)
		}
	}
	w := s.confirmDo(http.MethodPost, "/council/confirm", "203.0.113.4", url.Values{"token": {"tok-throttle"}}.Encode())
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("third attempt = %d Retry-After=%q, want 429 with Retry-After", w.Code, w.Header().Get("Retry-After"))
	}
	if cs, err := s.store.GetTenantSession(context.Background(), "busy@example.com"); err != nil || cs.ConfirmToken == "" {
		t.Fatalf("a throttled POST consumed the token: %+v %v", cs, err)
	}
	// Another address is unaffected, and the GET never counts against the limit.
	if w := s.confirmDo(http.MethodGet, "/tenant/confirm?token=tok-throttle", "203.0.113.4", ""); w.Code != 200 {
		t.Fatalf("GET under a POST throttle = %d, want 200", w.Code)
	}
	if w := s.confirmDo(http.MethodPost, "/tenant/confirm", "203.0.113.99", body); w.Code != 200 {
		t.Fatalf("other address = %d, want 200", w.Code)
	}
}

// The public POST caps its body (limitBody): an oversized form is not parsed,
// so a token buried after a large filler field neither acts nor is consumed —
// and the request never buffers megabytes for an anonymous caller.
func TestTenantConfirmLimitsBody(t *testing.T) {
	s := newAuthzServer(t)
	seedConfirmToken(t, s, "big@example.com", "tok-big")

	pad := strings.Repeat("a", maxFormBytes+1024)
	body := url.Values{"filler": {pad}, "token": {"tok-big"}}.Encode()
	w := s.confirmDo(http.MethodPost, "/tenant/confirm", "203.0.113.5", body)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Nothing to do here") {
		t.Fatalf("oversized POST = %d %s, want the stale page (form not parsed)", w.Code, excerpt(w.Body.String()))
	}
	if cs, err := s.store.GetTenantSession(context.Background(), "big@example.com"); err != nil || cs.ConfirmToken == "" {
		t.Fatalf("an oversized POST consumed the token: %+v %v", cs, err)
	}
	// A normal-sized POST with the same token still works afterwards.
	ok := s.confirmDo(http.MethodPost, "/tenant/confirm", "203.0.113.5", url.Values{"token": {"tok-big"}}.Encode())
	if ok.Code != 200 || !strings.Contains(ok.Body.String(), "keep running") {
		t.Fatalf("follow-up POST = %d %s", ok.Code, excerpt(ok.Body.String()))
	}
}
