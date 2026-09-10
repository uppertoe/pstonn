package server

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/notify"
)

// newContactServer is a contact-enabled server whose only outbound channels are
// a fake ntfy server and a mailer that records every send. The mailer exists to
// prove the form never touches it.
func newContactServer(t *testing.T) (*Server, *fakeNtfy, *[]string) {
	t.Helper()
	s := newAuthzServer(t)
	s.cfg.ContactForm = true
	s.cfg.PublicBaseURL = "https://app.example.com"
	s.contact = newRateLimiter(100, time.Minute)
	f := &fakeNtfy{}
	ts := httptest.NewServer(f)
	t.Cleanup(ts.Close)
	var mailed []string
	m := &mailer.Mailer{SendHook: func(to, subject, body string, o mailer.Options) error {
		mailed = append(mailed, to+": "+subject)
		return nil
	}}
	s.mail = m
	s.notify = notify.New(s.store, m, ts.URL, "", "https://app.example.com", "admin@example.com", "admin-topic", time.UTC, nil,
		notify.DeriveDecideKey(bytes.Repeat([]byte{7}, 32)))
	return s, f, &mailed
}

func postContact(s *Server, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/contact", strings.NewReader(form.Encode()))
	r.Host = "app.example.com"
	r.RemoteAddr = "10.0.0.2:41000"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// TestContactStoresAndPushesNeverMails: a submission is kept for /admin and
// pushed to the admin topic, and NOTHING goes through the mailer — not to the
// operator, and never with the stranger's address as a Reply-To. Relaying the
// form by email is how bot spam left the server DKIM-signed by our own domain.
func TestContactStoresAndPushesNeverMails(t *testing.T) {
	s, f, mailed := newContactServer(t)
	w := postContact(s, url.Values{"message": {"Hello there, my permit shows the wrong car."}, "email": {"someone@mail.example"}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Your message has been sent") {
		t.Fatalf("status %d, body %q", w.Code, w.Body.String())
	}
	msgs, err := s.store.ListContactMessages(context.Background(), 10)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("stored messages = %v, %v; want one", msgs, err)
	}
	if msgs[0].Message != "Hello there, my permit shows the wrong car." || msgs[0].ReplyTo != "someone@mail.example" {
		t.Fatalf("stored %+v", msgs[0])
	}
	if len(*mailed) != 0 {
		t.Fatalf("the contact form sent email: %v", *mailed)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n != 1 {
		t.Fatalf("admin pushes = %d, want 1", f.n)
	}
	if got := f.last.Get("Title"); got != "p.stonn contact form" {
		t.Fatalf("push title %q", got)
	}
	if got := f.last.Get("Click"); got != "https://app.example.com/admin" {
		t.Fatalf("push Click %q, want the admin page", got)
	}
}

// TestContactHoneypotStoresNothing: a filled honeypot still reads as success to
// the poster but stores and pushes nothing.
func TestContactHoneypotStoresNothing(t *testing.T) {
	s, f, mailed := newContactServer(t)
	w := postContact(s, url.Values{"message": {"buy cheap things online today"}, "website": {"http://spam.example"}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Your message has been sent") {
		t.Fatalf("status %d, body %q", w.Code, w.Body.String())
	}
	if msgs, _ := s.store.ListContactMessages(context.Background(), 10); len(msgs) != 0 {
		t.Fatalf("honeypot hit was stored: %+v", msgs)
	}
	f.mu.Lock()
	n := f.n
	f.mu.Unlock()
	if n != 0 || len(*mailed) != 0 {
		t.Fatalf("honeypot hit reached a channel: pushes=%d mailed=%v", n, *mailed)
	}
}

// TestContactPushFailureStillStores: the push is a courtesy; a dead ntfy must
// not turn a stored message into "could not be sent" for the person writing.
func TestContactPushFailureStillStores(t *testing.T) {
	s, _, _ := newContactServer(t)
	s.notify = notify.New(s.store, nil, "http://127.0.0.1:1", "", "https://app.example.com", "", "admin-topic", time.UTC, nil,
		notify.DeriveDecideKey(bytes.Repeat([]byte{7}, 32)))
	w := postContact(s, url.Values{"message": {"The schedule page will not load for me."}})
	if !strings.Contains(w.Body.String(), "Your message has been sent") {
		t.Fatalf("body %q", w.Body.String())
	}
	if msgs, _ := s.store.ListContactMessages(context.Background(), 10); len(msgs) != 1 {
		t.Fatalf("stored = %d, want 1", len(msgs))
	}
}

// TestContactFormOffWithoutSwitch: neither CONTACT_FORM nor the legacy
// CONTACT_TO set means the page is not offered; the legacy address alone still
// switches it on so an unchanged deployment keeps its contact page.
func TestContactFormOffWithoutSwitch(t *testing.T) {
	s, _, _ := newContactServer(t)
	s.cfg.ContactForm = false
	if s.cfg.ContactEnabled() {
		t.Fatal("form enabled with no switch")
	}
	if w := postContact(s, url.Values{"message": {"a perfectly ordinary message"}}); w.Code != 303 {
		t.Fatalf("disabled form answered %d, want a redirect", w.Code)
	}
	s.cfg.ContactTo = "legacy@example.com"
	if !s.cfg.ContactEnabled() {
		t.Fatal("CONTACT_TO alone should keep the form on")
	}
}
