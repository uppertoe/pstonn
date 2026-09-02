package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
)

// A stateless signed cookie has nothing server-side to invalidate, so before the
// epoch existed "you are no longer an admin", "you no longer have access to this
// household" and "your account is deleted" all waited for the cookie to lapse on its
// own — up to the full session lifetime, admin rights included.

func issued(t *testing.T, m *Manager, u identity.User) string {
	t.Helper()
	w := httptest.NewRecorder()
	if err := m.Issue(w, u); err != nil {
		t.Fatalf("issue: %v", err)
	}
	return w.Result().Cookies()[0].Value
}

func TestRevocationRefusesEarlierSessions(t *testing.T) {
	m := testManager()
	u := identity.User{Email: "user@example.com", Groups: []string{"user", "admin"}}
	cookie := issued(t, m, u)

	// Before revocation it works.
	if _, ok, _ := m.decodeValue(cookie); !ok {
		t.Fatal("a freshly issued cookie should decode")
	}

	m.RevokeTo(u.Email, 1)

	if got, ok, _ := m.decodeValue(cookie); ok {
		t.Fatalf("a revoked session still decoded as %+v — losing access must take effect on the next request", got)
	}
}

// Revocation is per person, so one household member losing access must not sign out
// everybody else.
func TestRevocationIsScopedToOnePerson(t *testing.T) {
	m := testManager()
	alice := issued(t, m, identity.User{Email: "alice@example.com"})
	bob := issued(t, m, identity.User{Email: "bob@example.com"})

	m.RevokeTo("alice@example.com", 1)

	if _, ok, _ := m.decodeValue(alice); ok {
		t.Error("Alice's session survived her own revocation")
	}
	if _, ok, _ := m.decodeValue(bob); !ok {
		t.Error("Bob was signed out by Alice's revocation")
	}
}

// Signing in again after a revocation must work: the new cookie carries the new
// epoch, so revocation ends a session rather than locking a person out for good.
func TestSigningInAgainAfterRevocationWorks(t *testing.T) {
	m := testManager()
	u := identity.User{Email: "user@example.com"}
	old := issued(t, m, u)
	m.RevokeTo(u.Email, 1)
	if _, ok, _ := m.decodeValue(old); ok {
		t.Fatal("setup: the old cookie should be dead")
	}

	fresh := issued(t, m, u)
	if _, ok, _ := m.decodeValue(fresh); !ok {
		t.Fatal("a cookie issued after the revocation must be accepted")
	}
	// ...and the old one stays dead.
	if _, ok, _ := m.decodeValue(old); ok {
		t.Error("the pre-revocation cookie came back to life")
	}
}

// A revoked session must not be able to slide its own expiry forward on the way out.
func TestRevokedSessionIsNotRenewed(t *testing.T) {
	m := testManager()
	const email = "user@example.com"
	// Half-spent, so it would otherwise be renewed on this decode.
	v := m.mint(t, payload{
		Email: email,
		Exp:   time.Now().Add(time.Hour).Unix(),
		Iat:   time.Now().Add(-11 * time.Hour).Unix(),
	})
	m.RevokeTo(email, 1)

	r := httptest.NewRequest("GET", "/schedule", nil)
	r.AddCookie(&http.Cookie{Name: m.issuedCookieName(), Value: v})
	w := httptest.NewRecorder()
	if _, ok := m.Decode(w, r); ok {
		t.Fatal("a revoked session decoded")
	}
	if cookies := w.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("a revoked session was handed a renewed cookie: %+v", cookies)
	}
}

// Epochs survive a restart by being seeded from storage; a revocation that forgot
// itself on reboot would be no revocation at all.
func TestSeededEpochsRefuseOldSessions(t *testing.T) {
	issuer := testManager()
	cookie := issued(t, issuer, identity.User{Email: "User@Example.com"})

	// A fresh process, seeded from the store.
	restarted := testManager()
	restarted.SetEpochs(map[string]int64{"user@example.com": 1})

	if _, ok, _ := restarted.decodeValue(cookie); ok {
		t.Fatal("a revocation was forgotten across a restart")
	}
}

// Email is the key, and the rest of the app normalises case and whitespace, so this
// must too — otherwise "User@Example.com" and "user@example.com" are two people and a
// revocation silently misses.
func TestRevocationMatchesEmailCaseInsensitively(t *testing.T) {
	m := testManager()
	cookie := issued(t, m, identity.User{Email: "user@example.com"})

	m.RevokeTo("  User@Example.COM  ", 1)

	if _, ok, _ := m.decodeValue(cookie); ok {
		t.Fatal("a revocation spelled differently missed the session it was meant to end")
	}
}

// Nobody has an epoch until something is revoked, so the ordinary case must cost no
// row and behave exactly as before.
func TestUnrevokedSessionsAreUnaffected(t *testing.T) {
	m := testManager()
	m.SetEpochs(map[string]int64{"someone-else@example.com": 3})
	cookie := issued(t, m, identity.User{Email: "user@example.com"})
	if _, ok, _ := m.decodeValue(cookie); !ok {
		t.Fatal("a person with no epoch of their own was signed out")
	}
}
