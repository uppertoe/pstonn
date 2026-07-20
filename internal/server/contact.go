package server

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
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

// rateLimiter is a small fixed-window per-key throttle used by the public
// contact form: at most `limit` events per `window` for a given key (client IP).
// It is intentionally simple and in-memory; the contact form is low-volume and a
// process restart resetting the counters is acceptable.
type rateLimiter struct {
	limit  int
	window time.Duration
	mu     sync.Mutex
	hits   map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: make(map[string][]time.Time)}
}

// allow records an event for key and reports whether it is within the limit.
func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-rl.window)
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Drop stale timestamps for this key, and opportunistically prune others so
	// the map can't grow without bound.
	kept := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	for k, ts := range rl.hits {
		if k == key {
			continue
		}
		if len(ts) == 0 || ts[len(ts)-1].Before(cutoff) {
			delete(rl.hits, k)
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
// throttle). Falls back to the connection's remote address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
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
