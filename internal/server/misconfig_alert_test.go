package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/notify"
)

// Reaching a signed-in-only handler with no identity behind forward-auth is a
// deployment bug (a route missing from the proxy's forward-auth list, or a
// proxy-secret mismatch) that used to be a silent log line — it hid a two-day
// /tenant/link outage. It must now page the operator, once per window, naming
// the route.
func TestMisconfiguredRouteAlertsOperatorOncePerWindow(t *testing.T) {
	s := newAuthzServer(t)
	s.auth = nil // forward-auth mode (production posture)

	var mu sync.Mutex
	var subjects, bodies []string
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <x@stonn.org>"})
	m.SetSendHook(func(to, subject, body string, _ mailer.Options) error {
		mu.Lock()
		defer mu.Unlock()
		subjects = append(subjects, subject)
		bodies = append(bodies, body)
		return nil
	})
	// adminEmail set + a working mailer => AdminConfigured() true.
	s.notify = notify.New(s.store, m, "", "", "https://app.example.com", "ops@stonn.org", "", time.UTC, nil, nil)

	// Three hits on a protected route with no identity; NotifyAdmin runs in a
	// goroutine, so drive user() directly and wait for the send hook.
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest(http.MethodPost, "/tenant/link", nil)
		if _, ok := s.user(httptest.NewRecorder(), r); ok {
			t.Fatal("user() should not resolve an identity here")
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(subjects)
		mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(subjects) != 1 {
		t.Fatalf("want exactly one throttled alert, got %d: %v", len(subjects), subjects)
	}
	if !strings.Contains(bodies[0], "POST /tenant/link") {
		t.Fatalf("alert body should name the route, got: %s", bodies[0])
	}
}

// No admin channel (local/dev): the misconfig branch must not try to page anyone.
func TestMisconfiguredRouteSilentWithoutAdminChannel(t *testing.T) {
	s := newAuthzServer(t)
	s.auth = nil
	s.notify = notify.New(s.store, nil, "", "", "https://app.example.com", "", "", time.UTC, nil, nil) // no adminEmail/topic
	// Should simply not panic / not alert.
	r := httptest.NewRequest(http.MethodGet, "/vehicles", nil)
	if _, ok := s.user(httptest.NewRecorder(), r); ok {
		t.Fatal("unexpected identity")
	}
	if s.notify.AdminConfigured() {
		t.Fatal("test setup wrong: admin should be unconfigured")
	}
}
