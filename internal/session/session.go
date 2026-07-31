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
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
)

const cookieName = "pstonn_session"

// Manager issues and validates session cookies.
type Manager struct {
	secret []byte
	secure bool
	ttl    time.Duration
	// maxAge caps the whole session regardless of renewal. Sliding an expiry forward
	// on every visit is what stops an active user being cut off mid-task, but with no
	// ceiling it also means a cookie captured once is good forever. This bounds it:
	// after maxAge the user re-authenticates, which is also the only point at which
	// group membership (including admin) is re-read from the provider.
	maxAge time.Duration
	// epochs is the per-person revocation generation, guarded by mu. See SetEpochs.
	mu     sync.RWMutex
	epochs map[string]int64
}

// New builds a Manager. secure sets the cookie Secure flag (true in production).
func New(secret []byte, secure bool) *Manager {
	return &Manager{
		secret: secret, secure: secure,
		ttl: 12 * time.Hour, maxAge: 7 * 24 * time.Hour,
		epochs: make(map[string]int64),
	}
}

// SetEpochs seeds the revocation generations from storage at startup. Sessions
// issued before a person's current epoch are refused.
//
// Held in memory rather than read per request: this process is the only writer, so
// the map is authoritative once seeded, and the alternative is a query on the single
// SQLite connection the reconcile loop shares — for a value that is zero for almost
// everyone.
func (m *Manager) SetEpochs(epochs map[string]int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.epochs = make(map[string]int64, len(epochs))
	for k, v := range epochs {
		m.epochs[normalise(k)] = v
	}
}

// RevokeTo records a person's new epoch, so every cookie issued before it stops
// working immediately. Call it after the store has been bumped, with the value the
// store returned.
func (m *Manager) RevokeTo(email string, epoch int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.epochs[normalise(email)] = epoch
}

func (m *Manager) epochFor(email string) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.epochs[normalise(email)]
}

func normalise(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

type payload struct {
	Email  string   `json:"e"`
	Name   string   `json:"n"`
	Groups []string `json:"g"`
	Exp    int64    `json:"x"`
	// Iat is when the session first began (preserved across renewals) so maxAge can
	// be enforced. Cookies issued before this field existed decode it as 0; those are
	// honoured until their own Exp but never renewed, so the change signs nobody out.
	Iat int64 `json:"i,omitempty"`
	// Ep is the revocation generation this session was issued under. A cookie whose
	// Ep is behind the person's current epoch is refused — this is what makes a
	// stateless session revocable at all. Omitted (and so zero) for anyone who has
	// never had anything revoked, which is almost everyone.
	Ep int64 `json:"ep,omitempty"`
}

// Issue writes a signed session cookie for u, starting a new session.
func (m *Manager) Issue(w http.ResponseWriter, u identity.User) error {
	return m.issue(w, u, time.Now().Unix())
}

func (m *Manager) issue(w http.ResponseWriter, u identity.User, iat int64) error {
	body, err := json.Marshal(payload{
		Email:  u.Email,
		Name:   u.Name,
		Groups: u.Groups,
		Exp:    time.Now().Add(m.ttl).Unix(),
		Iat:    iat,
		Ep:     m.epochFor(u.Email),
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
// expiry, renews it when it is more than half spent, and returns the carried
// identity.
//
// Renewal is what makes a 12-hour TTL usable — otherwise someone mid-task is signed
// out at an arbitrary moment — while maxAge keeps the session from becoming
// permanent.
//
// The identity a cookie carries, groups included, is still a snapshot taken at
// sign-in: this does not re-read the provider on every request. What it does give is
// REVOCATION — bumping someone's epoch refuses every cookie issued before it, so
// losing access or having an account deleted takes effect on the next request rather
// than whenever the cookie happened to lapse. A group change that is not accompanied
// by a bump still waits for maxAge.
func (m *Manager) Decode(w http.ResponseWriter, r *http.Request) (identity.User, bool) {
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
	now := time.Now()
	if now.Unix() >= p.Exp {
		return identity.User{}, false
	}
	if p.Email == "" {
		return identity.User{}, false
	}
	u := identity.User{Email: p.Email, Name: p.Name, Groups: p.Groups}
	// Revoked: this cookie was issued under an older generation. Checked before the
	// renewal below, so a revoked session can never slide its own expiry forward.
	if p.Ep < m.epochFor(p.Email) {
		return identity.User{}, false
	}
	// Past the absolute ceiling: refuse rather than renew, so the user goes back
	// through the provider and their groups are re-read.
	if p.Iat != 0 && now.Sub(time.Unix(p.Iat, 0)) >= m.maxAge {
		return identity.User{}, false
	}
	// More than half spent, and renewable (Iat present, so not a legacy cookie):
	// slide the expiry forward, keeping the original start so maxAge still bites.
	// A failed re-issue is not fatal — the current cookie is still valid.
	if w != nil && p.Iat != 0 && time.Unix(p.Exp, 0).Sub(now) < m.ttl/2 {
		_ = m.issue(w, u, p.Iat)
	}
	return u, true
}

func (m *Manager) sign(b64 string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(b64))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
