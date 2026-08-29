package secretbox

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// NOTE: context binding (associated data, so a sealed blob cannot be moved between
// rows or columns and still open) is finding C5 in docs/security-review-2026-07-30.md
// and is implemented separately. The tests here cover the properties that hold
// regardless: confidentiality, integrity, key separation, and nonce freshness.

func testBox(t *testing.T, fill byte) *Box {
	t.Helper()
	b, err := New(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatalf("new box: %v", err)
	}
	return b
}

func TestNewRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := New(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Errorf("New accepted a %d-byte key; only 32 bytes is AES-256", n)
		}
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	b := testBox(t, 1)
	for _, plaintext := range []string{
		"",
		"a",
		"Permits.IDM.Identity=abc123; path=/",
		strings.Repeat("long cookie value ", 500),
		"unicode: café — naïve 🚗",
		"\x00\x01\x02 embedded control bytes",
	} {
		sealed, err := b.Seal(plaintext)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		// Check the raw ciphertext, not its base64 form, and only for a plaintext long
		// enough to be distinctive: a one- or two-character needle turns up in random
		// bytes by coincidence often enough to make the assertion flaky rather than
		// meaningful.
		if len(plaintext) >= 8 {
			raw, err := base64.StdEncoding.DecodeString(sealed)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if bytes.Contains(raw, []byte(plaintext)) {
				t.Errorf("the plaintext is visible in the ciphertext")
			}
		}
		got, err := b.Open(sealed)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if got != plaintext {
			t.Errorf("roundtrip = %q, want %q", got, plaintext)
		}
	}
}

// The whole point of sealing the tenant session is that a leaked database file
// does not yield usable credentials, so a different key must not open it.
func TestOpenWithWrongKeyFails(t *testing.T) {
	sealed, err := testBox(t, 1).Seal("Permits.IDM.Identity=secret")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := testBox(t, 2).Open(sealed); err == nil {
		t.Fatal("a box with a different key must not open this ciphertext")
	}
}

// AES-GCM is authenticated: any edit anywhere must be detected rather than
// producing garbage plaintext the caller might act on.
func TestTamperIsDetected(t *testing.T) {
	b := testBox(t, 1)
	sealed, err := b.Seal("active registration ABC123")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, i := range []int{0, len(raw) / 2, len(raw) - 1} {
		bad := bytes.Clone(raw)
		bad[i] ^= 0x01
		if _, err := b.Open(base64.StdEncoding.EncodeToString(bad)); err == nil {
			t.Errorf("flipping byte %d went undetected", i)
		}
	}
	// Truncation must fail too, including below the nonce length.
	for _, n := range []int{0, 1, 11, len(raw) - 1} {
		if _, err := b.Open(base64.StdEncoding.EncodeToString(raw[:n])); err == nil {
			t.Errorf("a %d-byte ciphertext was accepted", n)
		}
	}
}

func TestOpenRejectsMalformedInput(t *testing.T) {
	b := testBox(t, 1)
	for _, s := range []string{"", "not base64!!", "$$$$"} {
		if _, err := b.Open(s); err == nil {
			t.Errorf("Open(%q) should fail", s)
		}
	}
}

// A repeated nonce under the same key breaks GCM outright, so freshness per Seal is
// load-bearing, not cosmetic. Same plaintext, different ciphertext, every time.
func TestNoncesAreFresh(t *testing.T) {
	b := testBox(t, 1)
	const n = 200
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		sealed, err := b.Seal("the same plaintext every time")
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		raw, err := base64.StdEncoding.DecodeString(sealed)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		nonce := string(raw[:12])
		if seen[nonce] {
			t.Fatal("a nonce repeated under the same key")
		}
		seen[nonce] = true
	}
}
