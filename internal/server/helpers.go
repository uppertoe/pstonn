package server

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// formError reports a user-facing validation problem for a form submission. For
// an htmx request it returns 422 with the bare message, which the client turns
// into a toast (htmx does NOT swap non-2xx bodies, so returning an error page
// here would be silently dropped — the form would appear to do nothing). For a
// normal request it falls back to a full page. The 422 also keeps detail.successful
// false, so a modal wired to close only on success stays open for a retry.
func (s *Server) formError(w http.ResponseWriter, r *http.Request, msg string) {
	if r.Header.Get("HX-Request") != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, msg)
		return
	}
	s.message(w, http.StatusBadRequest, msg)
}

func (s *Server) message(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	// Escape msg: callers pass server-constructed strings today, but escaping
	// here removes the reflected-XSS foot-gun if a future caller ever forwards
	// user input into this sink.
	//
	// Always offer a way onward. This page is where most failures land (a refused
	// council link, a permit another account already manages, a rejected form),
	// and for several of them the only real recourse is a human — so when the
	// contact form is configured, link it here rather than leaving "← Back" as the
	// only affordance.
	contact := ""
	if s.cfg != nil && s.cfg.ContactEnabled() {
		contact = ` &middot; <a href="/contact">Contact us</a>`
	}
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><body style="font:16px system-ui;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#1a2233">`+
		`<p>%s</p><p><a href="/">&larr; Back</a>%s</p>`, template.HTMLEscapeString(msg), contact)
}

// safeLinkHref reports whether href may be emitted as an href by the helpers
// below. HTMLEscapeString stops an attacker breaking out of the attribute but
// says nothing at all about the SCHEME, so `javascript:alert(1)` survives it
// verbatim — and these two pages are the only markup in the app built outside
// html/template, whose contextual autoescaper would have applied exactly this
// check for us. Both callers pass s.logoutURL() today, so nothing is reachable;
// the allowlist is here so that stays true of the next caller.
//
// Permitted: a root-relative path, or an absolute http/https URL (the operator's
// AUTH_LOGOUT_URL is off-host). Refused: any other scheme, and a scheme-relative
// "//host" or "/\host", which browsers read as an authority and which would
// silently send someone to another origin.
func safeLinkHref(href string) bool {
	if href == "" || strings.Contains(href, `\`) {
		return false
	}
	u, err := url.Parse(href)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "http", "https":
		return u.Host != ""
	case "":
		return u.Host == "" && strings.HasPrefix(href, "/")
	default:
		return false
	}
}

// messageWithLink is message with an inline action link rendered as real
// markup. Callers must never concatenate HTML into msg — message() escapes it,
// which is exactly right for text and turns embedded tags into literal angle
// brackets. after is escaped text following the link (e.g. a trailing clause).
// An href that fails safeLinkHref degrades to the plain message: losing an
// affordance is recoverable, emitting a hostile link is not.
func (s *Server) messageWithLink(w http.ResponseWriter, code int, msg, label, href, after string) {
	if !safeLinkHref(href) {
		log.Printf("messageWithLink: refusing unsafe href %q, rendering message without the link", href)
		s.message(w, code, msg)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><body style="font:16px system-ui;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#1a2233">`+
		`<p>%s <a href="%s">%s</a>%s</p><p><a href="/">&larr; Back</a></p>`,
		template.HTMLEscapeString(msg), template.HTMLEscapeString(href),
		template.HTMLEscapeString(label), template.HTMLEscapeString(after))
}

func (s *Server) serverError(w http.ResponseWriter, err error) {
	log.Printf("server error: %v", err)
	s.message(w, http.StatusInternalServerError, "Something went wrong. Please try again.")
}

func redirectHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/schedule", http.StatusSeeOther)
}

func normalizeReg(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
}

// validRego reports whether s (already normalised: upper-case, no spaces) is a
// plausible number plate: 2–8 alphanumeric characters. It is a sanity gate to
// catch typos and junk, not a strict format check — Australian plates vary by
// state and custom plates differ, so we stay lenient; the council makes the
// authoritative check when the plate is actually set.
func validRego(s string) bool {
	if len(s) < 2 || len(s) > 8 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func pathInt(r *http.Request, name string) int64 { return atoi64(r.PathValue(name)) }

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// clampHour parses an hour-of-day field (0-23), falling back to def if empty or
// out of range.
func clampHour(s string, def int) int {
	t := strings.TrimSpace(s)
	if t == "" {
		return def
	}
	n, err := strconv.Atoi(t)
	if err != nil || n < 0 || n > 23 {
		return def
	}
	return n
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}
