package notify

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestDecideTokenRoundTrip: a minted token verifies only for its own request id
// and recipient, and dies at its expiry.
func TestDecideTokenRoundTrip(t *testing.T) {
	key := DeriveDecideKey(bytes.Repeat([]byte{7}, 32))
	if key == nil {
		t.Fatal("derive returned nil for a full-length data key")
	}
	now := time.Now()
	tok := decideToken(key, 41, "Mum@Example.com", now.Add(time.Hour))

	if !verifyDecideTokenAt(key, 41, "mum@example.com", tok, now) {
		t.Error("token did not verify for its own id + case-normalised address")
	}
	if verifyDecideTokenAt(key, 42, "mum@example.com", tok, now) {
		t.Error("token verified for a DIFFERENT request id")
	}
	if verifyDecideTokenAt(key, 41, "dad@example.com", tok, now) {
		t.Error("token verified for a DIFFERENT recipient")
	}
	if verifyDecideTokenAt(key, 41, "mum@example.com", tok, now.Add(2*time.Hour)) {
		t.Error("token verified after its expiry")
	}
	other := DeriveDecideKey(bytes.Repeat([]byte{9}, 32))
	if verifyDecideTokenAt(other, 41, "mum@example.com", tok, now) {
		t.Error("token verified under a different key")
	}
}

// TestDecideKeyFailsClosed: no at-rest key means no decide key, no links, and
// nothing verifies — never a forgeable constant-key token.
func TestDecideKeyFailsClosed(t *testing.T) {
	if DeriveDecideKey(nil) != nil {
		t.Fatal("derived a decide key from an empty data key")
	}
	if VerifyDecideToken(nil, 41, "a@b.c", "1.zzzz.mac") {
		t.Error("nil key verified a token")
	}
	svc := New(nil, nil, "", "", "https://p.example", "", "", time.UTC, nil, nil)
	if url := svc.GuestDecideURL(41, "a@b.c"); url != "" {
		t.Errorf("keyless service still minted a link: %q", url)
	}
}

// TestDecideKeyDomainSeparation: the decide key and the unsubscribe key derive
// from the same at-rest key but must never be interchangeable — a token minted
// under one must not verify under the other's key.
func TestDecideKeyDomainSeparation(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 32)
	dk, uk := DeriveDecideKey(data), DeriveUnsubKey(data)
	if bytes.Equal(dk, uk) {
		t.Fatal("decide key equals unsubscribe key")
	}
	tok := decideToken(dk, 41, "a@b.c", time.Now().Add(time.Hour))
	if verifyDecideTokenAt(uk, 41, "a@b.c", tok, time.Now()) {
		t.Error("decide token verified under the unsubscribe key")
	}
}

// TestGuestDecideURLShape: the link points at /r/{id}/{addr}/{token} on the
// public base and round-trips through verification.
func TestGuestDecideURLShape(t *testing.T) {
	svc := New(nil, nil, "", "", "https://p.example", "", "", time.UTC, nil, DeriveDecideKey(bytes.Repeat([]byte{7}, 32)))
	url := svc.GuestDecideURL(41, "mum@example.com")
	if url == "" || !strings.HasPrefix(url, "https://p.example/r/41/") {
		t.Fatalf("unexpected link shape: %q", url)
	}
	parts := strings.Split(strings.TrimPrefix(url, "https://p.example/r/41/"), "/")
	if len(parts) != 2 {
		t.Fatalf("link path has %d segments after the id, want 2: %q", len(parts), url)
	}
	addr, ok := DecodeUnsubAddress(parts[0])
	if !ok || addr != "mum@example.com" {
		t.Fatalf("address segment decoded to %q (ok=%v)", addr, ok)
	}
	if !VerifyDecideToken(svc.decideKey, 41, addr, parts[1]) {
		t.Error("minted link's token failed verification")
	}
}
