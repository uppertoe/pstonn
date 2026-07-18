// Package session implements a stateless, HMAC-signed session cookie for the
// app's own logged-in users. It mirrors the vps-scaffold-auth approach: no
// server-side session store, just a signed, expiring cookie. The signed
// identity is populated by the OIDC login (internal/webauth).
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
)

const cookieName = "pstonn_session"

// Manager issues and validates session cookies.
type Manager struct {
	secret []byte
	secure bool
	ttl    time.Duration
}

// New builds a Manager. secure sets the cookie Secure flag (true in production).
func New(secret []byte, secure bool) *Manager {
	return &Manager{secret: secret, secure: secure, ttl: 12 * time.Hour}
}

type payload struct {
	Email  string   `json:"e"`
	Name   string   `json:"n"`
	Groups []string `json:"g"`
	Exp    int64    `json:"x"`
}

// Issue writes a signed session cookie for u.
func (m *Manager) Issue(w http.ResponseWriter, u identity.User) error {
	body, err := json.Marshal(payload{
		Email:  u.Email,
		Name:   u.Name,
		Groups: u.Groups,
		Exp:    time.Now().Add(m.ttl).Unix(),
	})
	if err != nil {
		return err
	}
	b64 := base64.RawURLEncoding.EncodeToString(body)
	value := b64 + "." + m.sign(b64)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(m.ttl),
		MaxAge:   int(m.ttl.Seconds()),
	})
	return nil
}

// Clear removes the session cookie.
func (m *Manager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// Decode implements identity.Decoder: it validates the cookie signature and
// expiry and returns the carried identity.
func (m *Manager) Decode(r *http.Request) (identity.User, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return identity.User{}, false
	}
	b64, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(m.sign(b64))) {
		return identity.User{}, false
	}
	body, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return identity.User{}, false
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return identity.User{}, false
	}
	if time.Now().Unix() >= p.Exp {
		return identity.User{}, false
	}
	return identity.User{Email: p.Email, Name: p.Name, Groups: p.Groups}, p.Email != ""
}

func (m *Manager) sign(b64 string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(b64))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
