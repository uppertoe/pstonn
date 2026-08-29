package server

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/uppertoe/pstonn/internal/model"
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

// message renders the branded notice page: the terminal answer for most
// guards and failures (a refused tenant link, a throttle, an invalid signed
// link). It styles through the normal template set so errors stop looking
// like a different, broken product — with the old dependency-free bare page
// kept underneath as the fallback, because this sink is also where render()
// itself lands when the template set is the thing that is broken.
func (s *Server) message(w http.ResponseWriter, code int, msg string) {
	s.messagePage(w, code, messageView{Text: msg})
}

func (s *Server) messagePage(w http.ResponseWriter, code int, mv messageView) {
	// A Server built without config (some tests) can't fill the page chrome;
	// the bare page needs nothing.
	if s.cfg == nil {
		s.bareMessage(w, code, mv)
		return
	}
	data := dashboardData{State: "message", Loc: s.cfg.DisplayLocation, Contact: s.cfg.ContactEnabled(), Message: &mv}
	buf, err := s.renderBuf(w, data)
	if err != nil {
		log.Printf("render message page: %v", err)
		s.bareMessage(w, code, mv)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = buf.WriteTo(w)
}

// bareMessage is the last-resort page: hand-built markup with zero template
// dependencies, so it can report a broken template set. Escape everything:
// callers pass server-constructed strings today, but escaping here removes
// the reflected-XSS foot-gun if a future caller ever forwards user input.
// Always offer a way onward — for several of the failures that land here the
// only real recourse is a human, so link the contact form when configured.
func (s *Server) bareMessage(w http.ResponseWriter, code int, mv messageView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	contact := ""
	if s.cfg != nil && s.cfg.ContactEnabled() {
		contact = ` &middot; <a href="/contact">Contact us</a>`
	}
	link := ""
	if mv.LinkLabel != "" && safeLinkHref(mv.LinkHref) {
		link = fmt.Sprintf(` <a href="%s">%s</a>%s`, template.HTMLEscapeString(mv.LinkHref),
			template.HTMLEscapeString(mv.LinkLabel), template.HTMLEscapeString(mv.After))
	}
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><body style="font:16px system-ui;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#1a2233">`+
		`<p>%s%s</p><p><a href="/">&larr; Back</a>%s</p>`, template.HTMLEscapeString(mv.Text), link, contact)
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
	s.messagePage(w, code, messageView{Text: msg, LinkLabel: label, LinkHref: href, After: after})
}

func (s *Server) serverError(w http.ResponseWriter, err error) {
	log.Printf("server error: %v", err)
	s.message(w, http.StatusInternalServerError, "Something went wrong. Please try again.")
}

func redirectHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/schedule", http.StatusSeeOther)
}

// normalizeReg canonicalises user-typed plate input with the same rule every
// plate comparison uses (model.NormPlate). This used to be a second, narrower
// normaliser (ASCII spaces only), so a pasted plate carrying a tab, a
// non-breaking space, or a display hyphen ("ABC-123") failed validation with a
// message that never named the offending character — for input SamePlate would
// happily have matched.
func normalizeReg(s string) string { return model.NormPlate(s) }

// plateFormatMsg is the shared validation error for a plate that is not 2–8
// alphanumerics after normalisation. It nudges the reader toward the trap that
// actually produces fines — visually confusable characters — because the
// tenant will store whatever well-formed string it is given (see validRego).
const plateFormatMsg = "Enter a valid number plate: 2–8 letters and numbers, e.g. ABC123. " +
	"Check it against the plate itself — letter O vs zero 0 and letter I vs one 1 are easy to mix up."

// validRego reports whether s (already normalised: upper-case, no spaces) is a
// plausible number plate: 2–8 alphanumeric characters. It is a sanity gate to
// catch junk, not a strict format check — Australian plates vary by state and
// custom plates differ, so we stay lenient. Note what the tenant does NOT
// check: a live capture showed it stores any well-formed string, existing car
// or not, so a typo that stays alphanumeric ("ABC1230" for "ABCI23O") passes
// here, passes there, and is confirmed as success. The read-back confirmation
// dialog on plate entry (layout.html, data-plate-confirm) is the only guard
// for that class of mistake.
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

// notFound is the app-level 404: reached for unclaimed sub-paths of routed
// prefixes (the gateway already refuses unknown top-level paths). The wording
// covers the likeliest real cause — a truncated link from an email or chat.
func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.message(w, http.StatusNotFound,
		"There's nothing at this address. If you followed a link from an email or message, it may have been cut short — try copying the whole link.")
}
