package secretbox

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return raw
}

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// The attack this closes, concretely. One key seals four different secrets, and with
// no binding a ciphertext is just "something this key encrypted" — so anyone able to
// write a row could move a household's council PASSWORD ciphertext into a
// guest_token.token_sealed row, then open the door-QR page, whose whole job is to
// reprint the token it finds there. That turned the at-rest key into a
// plaintext-password oracle through an ordinary authenticated page.
func TestCiphertextCannotMoveBetweenColumns(t *testing.T) {
	b := testBox(t, 1)
	const owner = "victim@example.com"
	const password = "the-council-password"

	sealed, err := b.SealCtx(CouncilPassword(owner), password)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Same key, same household, but read as a guest token: must not open.
	if pt, legacy, err := b.OpenCtx(GuestToken(owner), sealed); err == nil {
		t.Fatalf("a council password opened as a guest token (legacy=%v, plaintext=%q) — the door-QR page would print it", legacy, pt)
	}
	// And every other purpose is equally refused.
	for _, ctx := range []string{CouncilCookie(owner), CouncilToken(owner)} {
		if _, _, err := b.OpenCtx(ctx, sealed); err == nil {
			t.Errorf("password ciphertext opened under context %q", ctx)
		}
	}
	// Its own context still works, or the binding would just be breakage.
	got, legacy, err := b.OpenCtx(CouncilPassword(owner), sealed)
	if err != nil || got != password {
		t.Fatalf("own context failed to open: %q %v", got, err)
	}
	if legacy {
		t.Error("a freshly sealed value must not report as legacy")
	}
}

// The second half of the binding: one household's blob must not open as another's,
// so a row swap between accounts cannot hand over a live council session.
func TestCiphertextCannotMoveBetweenHouseholds(t *testing.T) {
	b := testBox(t, 1)
	const cookie = "Permits.IDM.Identity=live-session"

	sealed, err := b.SealCtx(CouncilCookie("alice@example.com"), cookie)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if pt, _, err := b.OpenCtx(CouncilCookie("bob@example.com"), sealed); err == nil {
		t.Fatalf("Alice's session cookie opened as Bob's (%q) — Bob would be driving her council account", pt)
	}
	if got, _, err := b.OpenCtx(CouncilCookie("alice@example.com"), sealed); err != nil || got != cookie {
		t.Fatalf("Alice's own context failed: %q %v", got, err)
	}
}

// Production databases hold blobs written before binding existed. Refusing them would
// unlink every household at once — a worse outcome than the write-primitive-gated
// weakness — so they must still open, and must be reported so the caller can re-seal.
func TestLegacyUnboundCiphertextStillOpensAndIsReported(t *testing.T) {
	b := testBox(t, 1)
	const secret = "sealed-by-an-older-build"

	legacyBlob, err := b.Seal(secret) // the pre-binding format
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, legacy, err := b.OpenCtx(CouncilCookie("owner@example.com"), legacyBlob)
	if err != nil {
		t.Fatalf("a legacy ciphertext must still open: %v", err)
	}
	if got != secret {
		t.Fatalf("legacy open = %q, want %q", got, secret)
	}
	if !legacy {
		t.Error("a legacy ciphertext must be reported as such, or it will never be re-sealed")
	}
}

// Re-sealing is what ends the migration window: once bound, the value stops being
// interchangeable.
func TestResealingClosesTheLegacyWindow(t *testing.T) {
	b := testBox(t, 1)
	const owner = "owner@example.com"

	legacyBlob, _ := b.Seal("secret")
	plain, legacy, err := b.OpenCtx(CouncilPassword(owner), legacyBlob)
	if err != nil || !legacy {
		t.Fatalf("setup: %v legacy=%v", err, legacy)
	}
	rebound, err := b.SealCtx(CouncilPassword(owner), plain)
	if err != nil {
		t.Fatalf("reseal: %v", err)
	}
	// Now it is bound: the guest-token context can no longer open it.
	if _, _, err := b.OpenCtx(GuestToken(owner), rebound); err == nil {
		t.Error("a re-sealed value is still interchangeable; the binding did not take")
	}
	if _, legacy, err := b.OpenCtx(CouncilPassword(owner), rebound); err != nil || legacy {
		t.Errorf("re-sealed value should open bound and non-legacy: %v legacy=%v", err, legacy)
	}
}

// A different key must not open a bound ciphertext either — the AAD is integrity, not
// a substitute for the key.
func TestBoundCiphertextStillNeedsTheRightKey(t *testing.T) {
	sealed, err := testBox(t, 1).SealCtx(CouncilCookie("o@example.com"), "secret")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, _, err := testBox(t, 2).OpenCtx(CouncilCookie("o@example.com"), sealed); err == nil {
		t.Fatal("another key opened a bound ciphertext")
	}
}

// The AAD is authenticated, not encrypted, so it must not leak into the ciphertext in
// a way that changes its length in step with the context — and more importantly, the
// contexts themselves must be distinct for values that must not be interchangeable.
func TestContextsAreDistinct(t *testing.T) {
	const a, b = "alice@example.com", "bob@example.com"
	all := []string{
		CouncilCookie(a), CouncilToken(a), CouncilPassword(a), GuestToken(a),
		CouncilCookie(b), CouncilToken(b), CouncilPassword(b), GuestToken(b),
	}
	seen := make(map[string]bool, len(all))
	for _, c := range all {
		if c == "" {
			t.Fatal("an empty context would bind nothing")
		}
		if seen[c] {
			t.Fatalf("duplicate context %q — two values that must not be interchangeable share a binding", c)
		}
		seen[c] = true
	}
}

// Tamper detection must still hold with a context in play.
func TestBoundCiphertextDetectsTamper(t *testing.T) {
	box := testBox(t, 1)
	ctx := CouncilPassword("o@example.com")
	sealed, err := box.SealCtx(ctx, "the-council-password")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw := decodeB64(t, sealed)
	for _, i := range []int{0, len(raw) / 2, len(raw) - 1} {
		bad := bytes.Clone(raw)
		bad[i] ^= 0x01
		if _, _, err := box.OpenCtx(ctx, encodeB64(bad)); err == nil {
			t.Errorf("flipping byte %d went undetected", i)
		}
	}
}
