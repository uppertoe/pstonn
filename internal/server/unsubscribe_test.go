package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/store"
)

func newUnsubServer(t *testing.T) (*Server, *notify.Service) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "unsub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// 32 bytes: DeriveUnsubKey refuses anything shorter, because a key derived from
	// a short secret is guessable and an unsubscribe link must not be forgeable.
	key := notify.DeriveUnsubKey([]byte("test-at-rest-key-0123456789abcdef"))
	svc := notify.New(st, nil, "", "", "https://app.example.com", "", "", time.UTC, key)
	return &Server{
		cfg:      &config.Config{DisplayLocation: time.UTC},
		store:    st,
		terms:    loadTerms(""),
		unsubKey: key,
	}, svc
}

// TestUnsubscribeFlow: the emailed link must stop mail, but only via a POST (a
// link-prefetching mail client must not unsubscribe anyone), and only for the one
// address the token was issued for.
func TestUnsubscribeFlow(t *testing.T) {
	s, svc := newUnsubServer(t)
	ctx := context.Background()
	const victim = "guest@example.com"

	link := svc.UnsubscribeURL(victim)
	if link == "" || !strings.HasPrefix(link, "https://app.example.com/u/") {
		t.Fatalf("unsubscribe URL = %q", link)
	}
	path := strings.TrimPrefix(link, "https://app.example.com")

	do := func(method, p string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, p, strings.NewReader(""))
		r.Host = "app.example.com"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}

	t.Run("GET only confirms, never acts", func(t *testing.T) {
		w := do("GET", path)
		if w.Code != http.StatusOK {
			t.Fatalf("GET = %d, want 200", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Stop emails to this address?") {
			t.Fatal("GET should render a confirmation, not act")
		}
		if bad, _, _ := s.store.IsSuppressed(ctx, victim); bad {
			t.Fatal("a GET (prefetch) unsubscribed the address")
		}
	})

	t.Run("POST stops mail", func(t *testing.T) {
		if w := do("POST", path); w.Code != http.StatusOK {
			t.Fatalf("POST = %d, want 200", w.Code)
		}
		bad, reason, err := s.store.IsSuppressed(ctx, victim)
		if err != nil {
			t.Fatal(err)
		}
		if !bad || reason != store.SuppressUnsubscribed {
			t.Fatalf("after POST: suppressed=%v reason=%q", bad, reason)
		}
		// Idempotent: a one-click header replay must not error.
		if w := do("POST", path); w.Code != http.StatusOK {
			t.Fatalf("repeat POST = %d, want 200", w.Code)
		}
	})

	t.Run("a token cannot unsubscribe a different address", func(t *testing.T) {
		const other = "someone-else@example.com"
		// Same (valid) token, swapped address in the path.
		parts := strings.Split(strings.TrimPrefix(path, "/u/"), "/")
		forged := "/u/" + base64.RawURLEncoding.EncodeToString([]byte(other)) + "/" + parts[1]
		if w := do("POST", forged); w.Code != http.StatusOK {
			t.Fatalf("forged POST = %d (want a 200 refusal page)", w.Code)
		}
		if bad, _, _ := s.store.IsSuppressed(ctx, other); bad {
			t.Fatal("a token issued for one address unsubscribed another")
		}
	})

	t.Run("garbage token is refused", func(t *testing.T) {
		p := "/u/" + base64.RawURLEncoding.EncodeToString([]byte("nobody@example.com")) + "/deadbeef"
		if w := do("POST", p); w.Code != http.StatusOK {
			t.Fatalf("bad token POST = %d", w.Code)
		}
		if bad, _, _ := s.store.IsSuppressed(ctx, "nobody@example.com"); bad {
			t.Fatal("an unsigned token unsubscribed an address")
		}
	})
}

// TestUnsubscribeThrottled: /u/* sits outside the CSRF gate (one-click posts
// cross-origin) and its token travels in a URL, so the per-IP throttle is the only
// thing pacing someone walking tokens or replaying one out of a forwarded email.
func TestUnsubscribeThrottled(t *testing.T) {
	s, svc := newUnsubServer(t)
	s.unsubLimit = newRateLimiter(1, time.Minute)
	path := strings.TrimPrefix(svc.UnsubscribeURL("guest@example.com"), "https://app.example.com")

	do := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "app.example.com"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := do(); w.Code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", w.Code)
	}
	w := do()
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("a shed request should say when to come back")
	}
}

// TestUnsubscribeUnsignedVersionedToken: the versioned token carries its own
// expiry, so an unsigned one is the shape an expired-or-edited link arrives in.
// It must fail closed with the same neutral wording as a forged one — the page is
// public, so it must not confirm whether an address is known to us. (The expiry
// itself is exercised in internal/notify, which owns the clock.)
func TestUnsubscribeUnsignedVersionedToken(t *testing.T) {
	s, _ := newUnsubServer(t)
	const victim = "guest@example.com"
	p := "/u/" + base64.RawURLEncoding.EncodeToString([]byte(victim)) + "/2.zzzzzzz.AAAAAAAAAAAAAAAAAAAAAA"
	r := httptest.NewRequest("POST", p, strings.NewReader(""))
	r.Host = "app.example.com"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expired token POST = %d, want a 200 refusal page", w.Code)
	}
	if !strings.Contains(w.Body.String(), "valid or has expired") {
		t.Error("an expired link should get the same neutral message as an invalid one")
	}
	if bad, _, _ := s.store.IsSuppressed(context.Background(), victim); bad {
		t.Fatal("an expired token unsubscribed the address")
	}
}

// TestUnsubscribeTokenBinding locks the token's scope at the crypto layer.
func TestUnsubscribeTokenBinding(t *testing.T) {
	// Two distinct 32-byte at-rest keys (the only length DeriveUnsubKey accepts).
	key := notify.DeriveUnsubKey([]byte("k1-0123456789abcdef0123456789abcd"))
	other := notify.DeriveUnsubKey([]byte("k2-0123456789abcdef0123456789abcd"))
	svc := notify.New(nil, nil, "", "", "https://app.example.com", "", "", time.UTC, key)

	link := svc.UnsubscribeURL("A@Example.com")
	tok := link[strings.LastIndex(link, "/")+1:]

	// Case-insensitive: the same mailbox typed differently verifies.
	if !notify.VerifyUnsubToken(key, "a@example.com", tok) {
		t.Fatal("token should verify for the same address in any case")
	}
	if notify.VerifyUnsubToken(key, "b@example.com", tok) {
		t.Fatal("token verified for a different address")
	}
	if notify.VerifyUnsubToken(other, "a@example.com", tok) {
		t.Fatal("token verified under a different key")
	}
	if notify.VerifyUnsubToken(key, "a@example.com", "") {
		t.Fatal("empty token verified")
	}
}
