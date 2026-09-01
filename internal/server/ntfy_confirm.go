package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/secretbox"
)

// ntfyConfirmTTL bounds how long the Confirm button on a test push keeps working.
// Long enough for someone who sends the test, then installs the app and finds the
// notification later that day; short enough that a token sitting in ntfy's message
// cache (12h by default) is dead soon after the cache forgets the message.
const ntfyConfirmTTL = 24 * time.Hour

// mintNtfyConfirm seals (owner, topic, expiry) into the token the test push's
// Confirm button posts back. The token, not a session, is the whole credential:
// the ntfy app sends the request with no cookie, from a phone that may never have
// signed in. Sealed rather than signed so the address never appears in the URL —
// the URL lands in ntfy's message cache and the phone's notification log. The
// topic is bound in so a confirmation minted before "New topic" cannot vouch for
// the topic that replaced it (ConfirmNtfy checks it against the row).
func (s *Server) mintNtfyConfirm(owner, topic string, exp time.Time) (string, error) {
	plain := owner + "\n" + topic + "\n" + strconv.FormatInt(exp.Unix(), 10)
	sealed, err := s.box.SealCtx(secretbox.NtfyConfirm(), plain)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", err
	}
	// URL-safe, unpadded: the token travels as a path segment.
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

var errNtfyConfirmExpired = errors.New("ntfy confirm token expired")

// openNtfyConfirm reverses mintNtfyConfirm. Any malformed or foreign blob is an
// error; a well-formed but aged-out one is errNtfyConfirmExpired.
func (s *Server) openNtfyConfirm(token string, now time.Time) (owner, topic string, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", "", err
	}
	plain, _, err := s.box.OpenCtx(secretbox.NtfyConfirm(), base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(plain, "\n")
	if len(parts) != 3 {
		return "", "", errors.New("ntfy confirm token: bad shape")
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", "", err
	}
	if now.Unix() > exp {
		return "", "", errNtfyConfirmExpired
	}
	return parts[0], parts[1], nil
}

// ntfyConfirm is the Confirm button on a test push posting back from the phone.
// Public and token-only (the ntfy app sends no session), so it is throttled like
// the other public token endpoints and reads nothing from the request beyond the
// path. A successful tap stamps the household's push channel as confirmed, which
// is what lets them turn email off (saveNotify). The response body is what the
// ntfy app shows in its toast, so it says what changed and where to look.
func (s *Server) ntfyConfirm(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	limitBody(r)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !s.confirmLimit.allow(rateLimitKey(r)) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many attempts. Please wait a moment.", http.StatusTooManyRequests)
		return
	}
	owner, topic, err := s.openNtfyConfirm(r.PathValue("token"), time.Now())
	switch {
	case errors.Is(err, errNtfyConfirmExpired):
		http.Error(w, "This confirmation has expired. Send a new test from p.stonn Settings and tap Confirm on that one.", http.StatusGone)
		return
	case err != nil:
		http.Error(w, "That confirmation link isn't valid.", http.StatusNotFound)
		return
	}
	stamped, err := s.store.ConfirmNtfy(r.Context(), owner, topic, time.Now())
	if err != nil {
		s.serverError(w, err)
		return
	}
	if !stamped {
		// Either already confirmed (a second tap) or the topic has since been
		// regenerated. Both are "nothing to do", and only the second needs a hint.
		if pref, perr := s.store.GetNotifyPref(r.Context(), owner); perr == nil && pref.NtfyTopic != topic {
			http.Error(w, "This test was for an older topic. Subscribe to your new topic, send a fresh test, and tap Confirm on that.", http.StatusGone)
			return
		}
		fmt.Fprintln(w, "Already confirmed. Push notifications are on for this phone.")
		return
	}
	log.Printf("ntfy confirmed for %s", redact.Email(owner))
	fmt.Fprintln(w, "Confirmed — push notifications are getting through to this phone. You can now turn off email in p.stonn Settings if you'd rather.")
}
