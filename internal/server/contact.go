package server

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
)

// isStateChanging reports whether the request mutates state (so it needs a CSRF
// same-origin check). GET/HEAD/OPTIONS are safe by convention.
func isStateChanging(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// sameOrigin is a CSRF defence for state-changing requests: it requires the
// Origin (or, failing that, Referer) host to match the request's own host. A
// cross-site form/fetch cannot forge a matching Origin, and browsers always send
// one on cross-origin POSTs. A state-changing request with neither header is
// rejected. This does not depend on cookie SameSite alone.
func sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		return err == nil && strings.EqualFold(u.Host, r.Host)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		return err == nil && strings.EqualFold(u.Host, r.Host)
	}
	return false
}

// rateLimiter is a small fixed-window per-key throttle: at most `limit` events
// per `window` for a given key (a client IP, an owner, a recipient address). It
// is intentionally simple and in-memory; a process restart resetting the
// counters is acceptable for every current use.
//
// Pruning is AMORTISED rather than per-call. A full map scan on every allow()
// turns the throttle itself into the bottleneck under exactly the traffic it
// exists to shed (a flood from many addresses is a scan of every key, under one
// mutex, per request). Instead: sweep every pruneEvery calls, and hard-cap the
// number of tracked keys so an attacker rotating addresses — trivial with IPv6
// — can't grow memory without bound.
type rateLimiter struct {
	limit  int
	window time.Duration
	mu     sync.Mutex
	hits   map[string][]time.Time
	calls  int // since the last sweep
}

// maxLimiterKeys bounds tracked keys. On overflow the map is cleared outright:
// crude, but it fails toward "allow" only briefly and never toward unbounded
// memory. Sized well above any legitimate concurrent-caller count.
const (
	maxLimiterKeys = 20000
	pruneEvery     = 256
)

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: make(map[string][]time.Time)}
}

// allow records an event for key and reports whether it is within the limit.
// A nil limiter allows everything: New always constructs them, so nil only
// happens in tests that build a Server directly — a throttle must never be the
// reason a handler panics on a public route.
func (rl *rateLimiter) allow(key string) bool {
	if rl == nil {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-rl.window)
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.calls++
	if rl.calls >= pruneEvery {
		rl.calls = 0
		for k, ts := range rl.hits {
			if k == key {
				continue
			}
			if len(ts) == 0 || ts[len(ts)-1].Before(cutoff) {
				delete(rl.hits, k)
			}
		}
	}
	// Still over the cap after a sweep (or between sweeps). Something has to go,
	// but NOT everything: clearing the whole map also clears the keys that are
	// currently AT the limit, and those are the only entries whose loss hands out
	// a free pass. Rotating addresses is cheap (an IPv6 /64 is effectively
	// unlimited), so a blanket wipe let an attacker keep the map saturated and
	// thereby keep resetting every real limiter — turning the memory guard into a
	// bypass for the throttle it was protecting.
	//
	// Keep the blocked keys, discard the rest. An attacker-chosen key seen once has
	// nothing worth remembering; a key that reached its limit does.
	if len(rl.hits) > maxLimiterKeys {
		blocked := make(map[string][]time.Time)
		for k, ts := range rl.hits {
			live := 0
			for _, t := range ts {
				if t.After(cutoff) {
					live++
				}
			}
			if live >= rl.limit {
				blocked[k] = ts
			}
		}
		// Only if the blocked set ALONE overflows do we give up and reset — that
		// costs an attacker `limit` requests per key rather than one, and there is
		// no bounded-memory alternative left.
		if len(blocked) > maxLimiterKeys {
			blocked = make(map[string][]time.Time)
		}
		rl.hits = blocked
	}

	// Drop this key's stale timestamps.
	kept := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rl.limit {
		rl.hits[key] = kept
		return false
	}
	rl.hits[key] = append(kept, now)
	return true
}

// clientIP extracts the caller's IP for rate-limiting. Behind the platform's
// single Caddy reverse proxy the trustworthy value is the RIGHTMOST
// X-Forwarded-For entry: Caddy appends the address it actually received the
// request from, while any earlier entries are client-supplied and spoofable
// (taking the leftmost would let an attacker rotate the header to defeat the
// throttle).
//
// X-Forwarded-For is only consulted when the request actually arrived from a
// proxy — judged by the peer being loopback or a private address, which is what a
// container network looks like. A request straight off the internet controls its
// own headers completely, so trusting them there would hand every caller a fresh
// limiter key per request and switch off every per-IP throttle in the app. In this
// deployment nothing reaches the app except through Caddy, but a self-hoster
// exposing the port directly should not silently lose their rate limits.
func clientIP(r *http.Request) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	if fromProxy(peer) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	return peer
}

// fromProxy reports whether a peer address is one we are willing to accept
// forwarding headers from: loopback, a private range, or a link-local address.
// An unparseable peer is treated as untrusted.
func fromProxy(peer string) bool {
	ip := net.ParseIP(peer)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// looksLikeEmail is a deliberately lenient sanity check (not RFC validation): a
// single @ with non-empty local and domain parts and a dot in the domain. Good
// enough to catch typos in an optional Reply-To without rejecting valid rarities.
func looksLikeEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at != strings.LastIndexByte(s, '@') || at == len(s)-1 {
		return false
	}
	domain := s[at+1:]
	if !strings.Contains(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	// Restrict to a conservative address charset. This covers real-world emails
	// (which use letters, digits, and . _ + - besides the @) while rejecting the
	// quotes, brackets, angle brackets and control characters that would let an
	// address break out of an HTML attribute, a JS string, or an email header.
	for _, r := range s {
		if r == '@' || r == '.' || r == '_' || r == '+' || r == '-' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// contactPage renders the PUBLIC contact form. When contact is not configured it
// redirects home rather than showing a dead form.
func (s *Server) contactPage(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.ContactEnabled() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_, signedIn := identity.FromContext(r.Context())
	s.render(w, dashboardData{State: "contact", SignedIn: signedIn, Contact: true, Loc: s.cfg.DisplayLocation})
}

// submitContact validates and delivers a contact-form message to the operator
// (CONTACT_TO) over the existing SMTP mailer. It is public and unauthenticated,
// so it is rate-limited per IP and carries a honeypot field; the submitter's
// address, if given, becomes the Reply-To. No user address is ever exposed.
func (s *Server) submitContact(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.ContactEnabled() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !sameOrigin(r) {
		s.message(w, http.StatusForbidden, "This request could not be verified. Please reload the page and try again.")
		return
	}
	_, signedIn := identity.FromContext(r.Context())
	base := dashboardData{State: "contact", SignedIn: signedIn, Contact: true, Loc: s.cfg.DisplayLocation}

	// Throttle BEFORE parsing: the limiter has to gate the expensive work (the
	// body parse), not just the send, or an unauthenticated flood still costs a
	// full form parse per request.
	if !s.contact.allow(clientIP(r)) {
		base.Warn = "You've sent a few messages already. Please wait a little while before sending another."
		s.render(w, base)
		return
	}
	limitBody(r)
	if err := r.ParseForm(); err != nil {
		base.Warn = "Could not read the form. Please try again."
		s.render(w, base)
		return
	}
	// Honeypot: a hidden field real users leave blank. Pretend success on a hit.
	if strings.TrimSpace(r.PostForm.Get("website")) != "" {
		base.Flash = "Thanks. Your message has been sent."
		s.render(w, base)
		return
	}

	message := strings.TrimSpace(r.PostForm.Get("message"))
	replyTo := strings.TrimSpace(r.PostForm.Get("email"))
	base.ContactVal, base.ContactFrom = message, replyTo

	if len(message) < 10 {
		base.Warn = "Please enter a message of at least a few words."
		s.render(w, base)
		return
	}
	if len(message) > 4000 {
		base.Warn = "That message is too long. Please shorten it to under 4000 characters."
		s.render(w, base)
		return
	}
	if replyTo != "" && !looksLikeEmail(replyTo) {
		base.Warn = "That doesn't look like a valid email address. Leave it blank or correct it."
		s.render(w, base)
		return
	}
	body := message
	if replyTo != "" {
		body += "\n\nReply-to: " + replyTo
	} else {
		body += "\n\n(No reply address given.)"
	}
	if err := s.mail.SendWithReplyTo(s.cfg.ContactTo, replyTo, "p.stonn contact form", body); err != nil {
		log.Printf("contact form send failed: %v", err)
		base.Warn = "Sorry, the message could not be sent right now. Please try again later."
		s.render(w, base)
		return
	}
	base.ContactVal, base.ContactFrom = "", "" // clear on success
	base.Flash = "Thanks. Your message has been sent."
	s.render(w, base)
}
