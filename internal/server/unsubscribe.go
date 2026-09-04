package server

import (
	"net/http"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/store"
)

// Unsubscribe is public and login-free by necessity: most people we email have no
// account at all — a visitor handed a guest pass, the contact for a car that came
// off a permit — and they are precisely the people entitled to make us stop. The
// link is a signed per-address token (see internal/notify/unsubscribe.go), so it
// can only ever stop mail to the one address it was issued for.
//
// GET renders a confirmation with a button; POST performs it. That split matters
// twice over: a link-prefetching mail client or corporate scanner must not be
// able to silently unsubscribe someone (the same mistake the renewal-confirm link
// made), and RFC 8058 one-click requires exactly this POST endpoint for the
// native "unsubscribe" button in Gmail and Yahoo to work. Getting that button is
// the goal — a complaint costs the whole sending domain's reputation, while an
// unsubscribe costs one address.
func (s *Server) unsubscribePage(w http.ResponseWriter, r *http.Request) {
	if s.unsubThrottled(w, r) {
		return
	}
	addr, ok := s.resolveUnsub(r)
	if !ok {
		// Deliberately vague and 200: this page is reachable by anyone, and
		// confirming whether an address is known to us would leak membership.
		s.message(w, http.StatusOK, "This unsubscribe link is no longer valid. If you are still receiving email you do not want, reply to any of it and it will be stopped.")
		return
	}
	noStore(w)
	s.render(w, dashboardData{
		State: "unsubscribe", Loc: s.cfg.DisplayLocation, Contact: s.cfg.ContactEnabled(),
		Unsub: &unsubView{Address: addr, Path: r.URL.Path},
	})
}

// unsubscribeApply stops email to the address. Idempotent: unsubscribing twice is
// the same as once, which is what a one-click header replay will do.
func (s *Server) unsubscribeApply(w http.ResponseWriter, r *http.Request) {
	if s.unsubThrottled(w, r) {
		return
	}
	addr, ok := s.resolveUnsub(r)
	if !ok {
		s.message(w, http.StatusOK, "This unsubscribe link is no longer valid. If you are still receiving email you do not want, reply to any of it and it will be stopped.")
		return
	}
	if err := s.store.SuppressAddress(r.Context(), addr, store.SuppressUnsubscribed, "unsubscribed via email link"); err != nil {
		s.serverError(w, err)
		return
	}
	alog.Infof("unsubscribe: %s opted out of email", notify.RedactEmail(addr))
	noStore(w)
	// A one-click POST from a mail provider wants a bare 200, not a page; a human
	// who pressed the button wants confirmation. Both get this — it is small, and
	// providers ignore the body.
	s.render(w, dashboardData{
		State: "unsubscribe", Loc: s.cfg.DisplayLocation, Contact: s.cfg.ContactEnabled(),
		Unsub: &unsubView{Address: addr, Done: true},
	})
}

// unsubThrottled sheds an unsubscribe request that is over the per-IP limit,
// reporting whether it did. This route sits outside the CSRF gate on purpose (RFC
// 8058 one-click posts cross-origin) and its token is a bearer capability that
// travels in a URL, so a throttle is the only thing pacing someone walking tokens
// or replaying one they found in a forwarded email. A real person clicks once.
func (s *Server) unsubThrottled(w http.ResponseWriter, r *http.Request) bool {
	if s.unsubLimit.allow(rateLimitKey(r)) {
		return false
	}
	w.Header().Set("Retry-After", "60")
	s.message(w, http.StatusTooManyRequests, "Too many requests. Please wait a moment and try again.")
	return true
}

// resolveUnsub validates the signed link and returns the address it authorises.
func (s *Server) resolveUnsub(r *http.Request) (string, bool) {
	addr, ok := notify.DecodeUnsubAddress(r.PathValue("addr"))
	if !ok {
		return "", false
	}
	if !notify.VerifyUnsubToken(s.unsubKey, addr, r.PathValue("token")) {
		return "", false
	}
	return addr, true
}
