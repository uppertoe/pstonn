package session

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
)

func testManager() *Manager { return New(bytes.Repeat([]byte{3}, 32), true) }

// mint builds a cookie value directly so a test can choose its expiry and start
// time without waiting. It signs with the manager's own key, so only the payload is
// under test, never the signature.
func (m *Manager) mint(t *testing.T, p payload) string {
	t.Helper()
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(body)
	return b64 + "." + m.sign(b64)
}

// decodeValue runs Decode against a request carrying the given cookie value and
// returns the identity plus any cookie the manager wrote back (the renewal).
func (m *Manager) decodeValue(value string) (identity.User, bool, []*http.Cookie) {
	r := httptest.NewRequest("GET", "/schedule", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: value})
	w := httptest.NewRecorder()
	u, ok := m.Decode(w, r)
	return u, ok, w.Result().Cookies()
}

func TestIssueThenDecode(t *testing.T) {
	m := testManager()
	w := httptest.NewRecorder()
	want := identity.User{Email: "user@example.com", Name: "A User", Groups: []string{"user", "admin"}}
	if err := m.Issue(w, want); err != nil {
		t.Fatalf("issue: %v", err)
	}
	cookies := w.Result().Cookies()
	// A secure manager issues under the __Host- name (which requires Secure + Path=/ +
	// no Domain — the properties that stop a sibling subdomain shadowing it).
	if len(cookies) != 1 || cookies[0].Name != hostCookieName {
		t.Fatalf("expected one %s cookie, got %+v", hostCookieName, cookies)
	}
	c := cookies[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("cookie attributes are wrong: %+v", c)
	}
	got, ok, _ := m.decodeValue(c.Value)
	if !ok || got.Email != want.Email || got.Name != want.Name || !got.IsAdmin() {
		t.Fatalf("roundtrip = %+v ok=%v, want %+v", got, ok, want)
	}
}

// The payload is signed, not encrypted, so the only thing standing between a user
// and self-promotion to admin is the MAC.
func TestTamperedPayloadIsRejected(t *testing.T) {
	m := testManager()
	valid := m.mint(t, payload{Email: "user@example.com", Exp: time.Now().Add(time.Hour).Unix(), Iat: time.Now().Unix()})
	b64, sig, _ := strings.Cut(valid, ".")

	forged, err := json.Marshal(payload{
		Email: "user@example.com", Groups: []string{"admin"},
		Exp: time.Now().Add(time.Hour).Unix(), Iat: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The original signature over a different body.
	swapped := base64.RawURLEncoding.EncodeToString(forged) + "." + sig
	if _, ok, _ := m.decodeValue(swapped); ok {
		t.Fatal("a payload swapped under an old signature must not verify")
	}
	// A mangled signature over the original body.
	if _, ok, _ := m.decodeValue(b64 + ".AAAA"); ok {
		t.Fatal("a bad signature must not verify")
	}
	// No separator at all.
	if _, ok, _ := m.decodeValue("garbage"); ok {
		t.Fatal("a malformed cookie must not verify")
	}
}

func TestDifferentSecretIsRejected(t *testing.T) {
	issuer := testManager()
	w := httptest.NewRecorder()
	if err := issuer.Issue(w, identity.User{Email: "user@example.com"}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	other := New(bytes.Repeat([]byte{9}, 32), true)
	if _, ok, _ := other.decodeValue(w.Result().Cookies()[0].Value); ok {
		t.Fatal("a cookie signed with another key must not verify")
	}
}

func TestExpiredIsRejected(t *testing.T) {
	m := testManager()
	v := m.mint(t, payload{Email: "user@example.com", Exp: time.Now().Add(-time.Second).Unix(), Iat: time.Now().Unix()})
	if _, ok, _ := m.decodeValue(v); ok {
		t.Fatal("an expired cookie must not verify")
	}
}

func TestEmptyEmailIsRejected(t *testing.T) {
	m := testManager()
	v := m.mint(t, payload{Exp: time.Now().Add(time.Hour).Unix(), Iat: time.Now().Unix()})
	if _, ok, _ := m.decodeValue(v); ok {
		t.Fatal("a cookie with no email must not authenticate anyone")
	}
}

// Renewal is what makes the TTL usable: an active user should never be signed out
// mid-task just because the clock ran out.
func TestRenewsWhenMoreThanHalfSpent(t *testing.T) {
	m := testManager()
	iat := time.Now().Add(-11 * time.Hour).Unix()
	v := m.mint(t, payload{Email: "user@example.com", Exp: time.Now().Add(time.Hour).Unix(), Iat: iat})

	u, ok, cookies := m.decodeValue(v)
	if !ok || u.Email != "user@example.com" {
		t.Fatalf("expected a valid session, got %+v ok=%v", u, ok)
	}
	if len(cookies) != 1 {
		t.Fatalf("expected a renewal cookie, got %d", len(cookies))
	}
	renewed := cookies[0].Value
	b64, _, _ := strings.Cut(renewed, ".")
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode renewed: %v", err)
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal renewed: %v", err)
	}
	if p.Iat != iat {
		t.Errorf("renewal reset Iat to %d, want the original %d — otherwise maxAge never bites", p.Iat, iat)
	}
	if time.Until(time.Unix(p.Exp, 0)) < 11*time.Hour {
		t.Errorf("renewal did not slide the expiry forward: %v", time.Until(time.Unix(p.Exp, 0)))
	}
}

func TestDoesNotRenewWhenFresh(t *testing.T) {
	m := testManager()
	v := m.mint(t, payload{Email: "user@example.com", Exp: time.Now().Add(11 * time.Hour).Unix(), Iat: time.Now().Unix()})
	if _, ok, cookies := m.decodeValue(v); !ok || len(cookies) != 0 {
		t.Fatalf("a fresh cookie should be left alone, got %d cookies (ok=%v)", len(cookies), ok)
	}
}

// The ceiling is what stops a renewed session becoming permanent — and it is the
// only thing that forces group membership to be re-read from the provider.
func TestAbsoluteMaxAgeIsEnforced(t *testing.T) {
	m := testManager()
	v := m.mint(t, payload{
		Email: "user@example.com",
		Exp:   time.Now().Add(time.Hour).Unix(),
		Iat:   time.Now().Add(-8 * 24 * time.Hour).Unix(),
	})
	if _, ok, _ := m.decodeValue(v); ok {
		t.Fatal("a session older than maxAge must be refused even while its Exp is live")
	}
}

// S1: a privileged (admin) session must be capped at the base ttl, not the full 7-day
// maxAge, so sliding renewal cannot carry a stale `admin` claim forward for a week
// after an IdP-side demotion. A non-admin session at the same age still lives.
func TestAdminSessionCappedAtTTL(t *testing.T) {
	m := testManager()
	// Aged 13h: past the 12h ttl but well within the 7-day maxAge.
	iat := time.Now().Add(-13 * time.Hour).Unix()
	adminV := m.mint(t, payload{
		Email:  "admin@example.com",
		Groups: []string{"user", "admin"},
		Exp:    time.Now().Add(time.Hour).Unix(),
		Iat:    iat,
	})
	if _, ok, _ := m.decodeValue(adminV); ok {
		t.Fatal("an admin session older than the base ttl must be refused, so a demotion cannot linger for the full maxAge")
	}
	userV := m.mint(t, payload{
		Email:  "user@example.com",
		Groups: []string{"user"},
		Exp:    time.Now().Add(time.Hour).Unix(),
		Iat:    iat,
	})
	if _, ok, _ := m.decodeValue(userV); !ok {
		t.Fatal("a non-admin session of the same age must still be valid (only privileged sessions are capped short)")
	}
}

// Cookies minted before Iat existed decode it as 0. They must keep working until
// their own expiry — a deploy that signs everyone out is its own kind of incident —
// but they must not be renewable, or they would live forever with no ceiling.
func TestLegacyCookieHonouredButNotRenewed(t *testing.T) {
	m := testManager()
	v := m.mint(t, payload{Email: "user@example.com", Exp: time.Now().Add(time.Minute).Unix()})
	u, ok, cookies := m.decodeValue(v)
	if !ok || u.Email != "user@example.com" {
		t.Fatalf("a legacy cookie should still authenticate, got %+v ok=%v", u, ok)
	}
	if len(cookies) != 0 {
		t.Fatalf("a legacy cookie must not be renewed, got %d cookies", len(cookies))
	}
}

func TestClearExpiresTheCookie(t *testing.T) {
	m := testManager()
	w := httptest.NewRecorder()
	m.Clear(w)
	cookies := w.Result().Cookies()
	// A secure manager expires BOTH the __Host- name and the legacy name, so a sign-out
	// clears whichever the browser is still holding across the rename.
	if len(cookies) != 2 {
		t.Fatalf("Clear must expire both cookie names, got %+v", cookies)
	}
	var sawHost bool
	for _, c := range cookies {
		if c.Value != "" || c.MaxAge >= 0 {
			t.Fatalf("Clear must send immediately-expiring empty cookies, got %+v", c)
		}
		if c.Name == hostCookieName {
			sawHost = true
		}
	}
	if !sawHost {
		t.Fatalf("Clear did not expire the __Host- cookie: %+v", cookies)
	}
}

func TestNoCookieIsAnonymous(t *testing.T) {
	m := testManager()
	r := httptest.NewRequest("GET", "/schedule", nil)
	if _, ok := m.Decode(httptest.NewRecorder(), r); ok {
		t.Fatal("a request with no cookie must not authenticate")
	}
}

// Decode must tolerate a nil writer so it can be used off the request path.
func TestDecodeWithNilWriter(t *testing.T) {
	m := testManager()
	v := m.mint(t, payload{Email: "user@example.com", Exp: time.Now().Add(time.Hour).Unix(), Iat: time.Now().Add(-11 * time.Hour).Unix()})
	r := httptest.NewRequest("GET", "/schedule", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: v})
	if _, ok := m.Decode(nil, r); !ok {
		t.Fatal("Decode must work without a ResponseWriter")
	}
}
