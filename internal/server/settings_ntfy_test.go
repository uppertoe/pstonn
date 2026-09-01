package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/store"
)

// fakeNtfy records every publish so a test can read the Actions header back.
type fakeNtfy struct {
	mu   sync.Mutex
	last http.Header
	n    int
}

func (f *fakeNtfy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last, f.n = r.Header.Clone(), f.n+1
	w.WriteHeader(http.StatusOK)
}

// confirmURL pulls the Confirm button's URL out of the last publish.
func (f *fakeNtfy) confirmURL(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	raw := f.last.Get("Actions")
	if raw == "" {
		return ""
	}
	var actions []struct {
		Action, Label, URL, Method string
		Clear                      bool
	}
	if err := json.Unmarshal([]byte(raw), &actions); err != nil {
		t.Fatalf("Actions header is not JSON: %v (%q)", err, raw)
	}
	if len(actions) != 1 || actions[0].Action != "http" || actions[0].Method != "POST" || !actions[0].Clear {
		t.Fatalf("unexpected actions: %+v", actions)
	}
	return actions[0].URL
}

func newNtfyServer(t *testing.T) (*Server, *fakeNtfy, string) {
	t.Helper()
	s := newAuthzServer(t)
	f := &fakeNtfy{}
	ts := httptest.NewServer(f)
	t.Cleanup(ts.Close)
	s.cfg.PublicBaseURL = "https://app.example.com"
	s.confirmLimit = newRateLimiter(100, time.Minute)
	s.testNotifyLimit = newRateLimiter(100, time.Minute)
	s.notify = notify.New(s.store, nil, ts.URL, "", "https://app.example.com", "", "", time.UTC, nil,
		notify.DeriveDecideKey(bytes.Repeat([]byte{7}, 32)))
	const user = "push@example.com"
	if err := s.store.RecordConsent(context.Background(), user, s.terms.Version, s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
	return s, f, user
}

// doHX is doReq as the Settings form sends it: over htmx, so the fragment (and
// its refusal message) comes back instead of a redirect to /settings.
func (s *Server) doHX(method, target, email, origin string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
	r.Host = "app.example.com"
	r.RemoteAddr = "10.0.0.2:41000"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("HX-Request", "true")
	r.Header.Set("Remote-Email", email)
	r.Header.Set("Remote-Groups", "user")
	r.Header.Set("Origin", origin)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func (s *Server) prefOf(t *testing.T, user string) store.NotifyPref {
	t.Helper()
	p, err := s.store.GetNotifyPref(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// postConfirm posts the Confirm button's URL through the router the way the
// ntfy app does: no session, no Origin, just the path.
func (s *Server) postConfirm(t *testing.T, confirmURL string) *httptest.ResponseRecorder {
	t.Helper()
	u, err := url.Parse(confirmURL)
	if err != nil {
		t.Fatal(err)
	}
	return s.doReq("POST", u.Path, "", "", nil)
}

// TestEmailOffRequiresConfirmedPush locks the flow: with push on but never
// confirmed, email cannot be switched off (server-side, regardless of the client
// guard); a test push carries a Confirm button; posting it stamps the channel;
// only then does the same toggle save — and "both off" stays refused throughout.
func TestEmailOffRequiresConfirmedPush(t *testing.T) {
	s, f, user := newNtfyServer(t)
	const origin = "http://app.example.com"
	ctx := context.Background()

	// Push on (topic minted), email on.
	if err := s.store.SetNotifyPref(ctx, store.NotifyPref{Owner: user, EmailEnabled: true, NtfyEnabled: true, NtfyTopic: notify.RandomTopic()}); err != nil {
		t.Fatal(err)
	}

	// 1. Untick email before confirming: refused, state unchanged, reason shown.
	w := s.doHX("POST", "/notifications", user, origin, url.Values{"ntfy_enabled": {"1"}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "⚠ You can turn off email once you&#39;ve confirmed push notifications") {
		t.Fatalf("unconfirmed email-off: code=%d body=%q", w.Code, w.Body.String())
	}
	if p := s.prefOf(t, user); !p.EmailEnabled || !p.NtfyEnabled {
		t.Fatalf("pref changed despite refusal: %+v", p)
	}

	// 2. The test push carries a Confirm button; the email side has none to carry.
	w = s.doReq("POST", "/notifications/test", user, origin, url.Values{})
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "confirm=1") {
		t.Fatalf("test: code=%d loc=%q", w.Code, w.Header().Get("Location"))
	}
	confirmURL := f.confirmURL(t)
	if !strings.HasPrefix(confirmURL, "https://app.example.com/ntfy/confirm/") {
		t.Fatalf("confirm url: %q", confirmURL)
	}
	if strings.Contains(confirmURL, "example.com/ntfy/confirm/"+user) || strings.Contains(strings.ToLower(confirmURL), "push%40") {
		t.Fatalf("address leaked into the confirm url: %q", confirmURL)
	}

	// 3. The phone taps Confirm: stamped, once.
	if w := s.postConfirm(t, confirmURL); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Confirmed") {
		t.Fatalf("confirm: code=%d body=%q", w.Code, w.Body.String())
	}
	p := s.prefOf(t, user)
	if !p.NtfyConfirmed() {
		t.Fatalf("not stamped: %+v", p)
	}
	first := p.NtfyConfirmedAt
	if w := s.postConfirm(t, confirmURL); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Already") {
		t.Fatalf("second tap: code=%d body=%q", w.Code, w.Body.String())
	}
	if s.prefOf(t, user).NtfyConfirmedAt != first {
		t.Fatal("second tap moved the timestamp")
	}

	// 4. A confirmed test push carries no button (nothing left to prove).
	s.doReq("POST", "/notifications/test", user, origin, url.Values{})
	if got := f.confirmURL(t); got != "" {
		t.Fatalf("confirmed channel still offered a Confirm button: %q", got)
	}

	// 5. Now email may go off …
	w = s.doHX("POST", "/notifications", user, origin, url.Values{"ntfy_enabled": {"1"}})
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "⚠ You can turn off email once you&#39;ve confirmed push notifications") {
		t.Fatalf("confirmed email-off: code=%d body=%q", w.Code, w.Body.String())
	}
	if p := s.prefOf(t, user); p.EmailEnabled || !p.NtfyEnabled {
		t.Fatalf("email-off not saved: %+v", p)
	}
	// … but never both.
	w = s.doHX("POST", "/notifications", user, origin, url.Values{})
	if !strings.Contains(w.Body.String(), "Keep at least one method on") {
		t.Fatalf("both-off accepted: body=%q", w.Body.String())
	}
	if p := s.prefOf(t, user); p.EmailEnabled || !p.NtfyEnabled {
		t.Fatalf("both-off changed state: %+v", p)
	}
	// And push-only → email-only is a plain swap.
	w = s.doHX("POST", "/notifications", user, origin, url.Values{"email_enabled": {"1"}})
	if p := s.prefOf(t, user); !p.EmailEnabled || p.NtfyEnabled {
		t.Fatalf("swap to email-only: code=%d %+v", w.Code, p)
	}
}

// TestNewTopicResetsConfirmation: "New topic" un-confirms (no device is on the
// new topic), and a push-only household gets email back until it is; a Confirm
// minted for the old topic cannot vouch for the new one.
func TestNewTopicResetsConfirmation(t *testing.T) {
	s, f, user := newNtfyServer(t)
	const origin = "http://app.example.com"
	ctx := context.Background()
	topic := notify.RandomTopic()
	if err := s.store.SetNotifyPref(ctx, store.NotifyPref{Owner: user, EmailEnabled: true, NtfyEnabled: true, NtfyTopic: topic}); err != nil {
		t.Fatal(err)
	}
	s.doReq("POST", "/notifications/test", user, origin, url.Values{})
	oldConfirm := f.confirmURL(t)
	s.postConfirm(t, oldConfirm)
	s.doHX("POST", "/notifications", user, origin, url.Values{"ntfy_enabled": {"1"}}) // push-only, allowed

	w := s.doHX("POST", "/notifications/regen-topic", user, origin, url.Values{})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Email is back on") {
		t.Fatalf("regen: code=%d body=%q", w.Code, w.Body.String())
	}
	p := s.prefOf(t, user)
	if p.NtfyConfirmed() || !p.EmailEnabled || !p.NtfyEnabled || p.NtfyTopic == topic {
		t.Fatalf("after regen: %+v", p)
	}
	// The old topic's Confirm is dead for the new topic.
	if w := s.postConfirm(t, oldConfirm); w.Code != http.StatusGone {
		t.Fatalf("stale-topic confirm: code=%d body=%q", w.Code, w.Body.String())
	}
	if s.prefOf(t, user).NtfyConfirmed() {
		t.Fatal("stale confirm stamped the new topic")
	}
	// A fresh test on the new topic confirms it.
	s.doReq("POST", "/notifications/test", user, origin, url.Values{})
	if w := s.postConfirm(t, f.confirmURL(t)); w.Code != http.StatusOK {
		t.Fatalf("fresh confirm: code=%d", w.Code)
	}
	if !s.prefOf(t, user).NtfyConfirmed() {
		t.Fatal("fresh confirm did not stamp")
	}
}

// TestNtfyConfirmTokenHygiene: garbage is 404, an aged-out token is 410, and a
// token sealed under a different context does not open.
func TestNtfyConfirmTokenHygiene(t *testing.T) {
	s, _, user := newNtfyServer(t)
	if w := s.doReq("POST", "/ntfy/confirm/not-a-token", "", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("garbage: %d", w.Code)
	}
	expired, err := s.mintNtfyConfirm(user, "pstonn-x", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if w := s.doReq("POST", "/ntfy/confirm/"+expired, "", "", nil); w.Code != http.StatusGone {
		t.Fatalf("expired: %d %q", w.Code, w.Body.String())
	}
	// Round-trip sanity for the encoder, and that the token binds owner+topic.
	tok, err := s.mintNtfyConfirm(user, "pstonn-x", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	o, tp, err := s.openNtfyConfirm(tok, time.Now())
	if err != nil || o != user || tp != "pstonn-x" {
		t.Fatalf("round trip: %q %q %v", o, tp, err)
	}
	if strings.ContainsAny(tok, "+/=") {
		t.Fatalf("token is not URL-safe: %q", tok)
	}
}

// TestPushOnlyTestButton: the button inside the push steps sends to the phone
// only, answers into the fragment with what to do next, carries the Confirm
// button while unconfirmed, and its confirmation is accepted like any other.
func TestPushOnlyTestButton(t *testing.T) {
	s, f, user := newNtfyServer(t)
	const origin = "http://app.example.com"
	ctx := context.Background()
	// Push off: nothing to send, and the fragment says so.
	if err := s.store.SetNotifyPref(ctx, store.NotifyPref{Owner: user, EmailEnabled: true, NtfyTopic: notify.RandomTopic()}); err != nil {
		t.Fatal(err)
	}
	w := s.doHX("POST", "/notifications/test-push", user, origin, url.Values{})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Turn on push notifications first") || f.n != 0 {
		t.Fatalf("push off: code=%d publishes=%d body=%q", w.Code, f.n, w.Body.String()[:200])
	}
	// Push on, unconfirmed: one publish, with the Confirm button, and the status
	// names the tap.
	if err := s.store.SetNotifyPref(ctx, store.NotifyPref{Owner: user, EmailEnabled: true, NtfyEnabled: true, NtfyTopic: notify.RandomTopic()}); err != nil {
		t.Fatal(err)
	}
	w = s.doHX("POST", "/notifications/test-push", user, origin, url.Values{})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "✓ Test sent to your phone — tap Confirm") || f.n != 1 {
		t.Fatalf("push on: code=%d publishes=%d", w.Code, f.n)
	}
	// The box shows the send where the finger is, and starts polling for the tap.
	if b := w.Body.String(); !strings.Contains(b, "<strong>Sent to your phone.</strong>") || !strings.Contains(b, `hx-get="/notifications/ntfy-status"`) || strings.Count(b, "Send a test to my phone</button>") != 1 {
		t.Fatalf("sent state not rendered in the box: %q", b[:400])
	}
	// Until the tap, the poll must leave the page alone (204, no body).
	if w := s.doHX("GET", "/notifications/ntfy-status", user, origin, url.Values{}); w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("poll before confirm: code=%d len=%d", w.Code, w.Body.Len())
	}
	if w := s.postConfirm(t, f.confirmURL(t)); w.Code != http.StatusOK {
		t.Fatalf("confirm from push-only test: %d", w.Code)
	}
	if !s.prefOf(t, user).NtfyConfirmed() {
		t.Fatal("not confirmed")
	}
	// After the tap, the poll returns the confirmed box and the poller is gone.
	if w := s.doHX("GET", "/notifications/ntfy-status", user, origin, url.Values{}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Your phone is set up") || strings.Contains(w.Body.String(), "ntfy-status") {
		t.Fatalf("poll after confirm: code=%d", w.Code)
	}
	// Confirmed: plain push, no button.
	w = s.doHX("POST", "/notifications/test-push", user, origin, url.Values{})
	if !strings.Contains(w.Body.String(), "✓ Test sent to your phone.") || f.n != 2 || f.confirmURL(t) != "" {
		t.Fatalf("confirmed push: publishes=%d actions=%q", f.n, f.confirmURL(t))
	}
}
