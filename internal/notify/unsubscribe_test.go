package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// realKey is a 32-byte at-rest key, the only length config accepts.
var realKey = []byte("0123456789abcdef0123456789abcdef")

// TestDeriveUnsubKeyRefusesShortKey (G8): hashing a missing key produced a
// perfectly usable 32-byte key that anyone can recompute — SHA-256 of a public
// constant — so a deployment with no DATA_ENCRYPTION_KEY was handing out
// unsubscribe tokens forgeable by anyone, and one forged token permanently
// suppresses an address. No key at all is the only safe answer.
func TestDeriveUnsubKeyRefusesShortKey(t *testing.T) {
	for _, dataKey := range [][]byte{nil, {}, []byte("short"), make([]byte, minDataKeyLen-1)} {
		if got := DeriveUnsubKey(dataKey); got != nil {
			t.Fatalf("DeriveUnsubKey(%d bytes) returned a %d-byte key, want none", len(dataKey), len(got))
		}
	}
	if got := DeriveUnsubKey(realKey); len(got) != unsubKeyLen {
		t.Fatalf("DeriveUnsubKey(32 bytes) = %d bytes, want %d", len(got), unsubKeyLen)
	}
}

// TestUnsubKeylessDeploymentIsNotForgeable: with no key, links are not offered and
// nothing verifies — including a token computed the way the old code would have,
// from the world-known constant.
func TestUnsubKeylessDeploymentIsNotForgeable(t *testing.T) {
	svc := New(nil, nil, "", "", "https://app.example.com", "", "", time.UTC, DeriveUnsubKey(nil), nil)
	if url := svc.UnsubscribeURL("guest@example.com"); url != "" {
		t.Fatalf("UnsubscribeURL with no signing key = %q, want no link at all", url)
	}
	// The forgeable key the old derivation produced for an empty at-rest key, and a
	// token anyone could have computed under it. Nothing the app holds may accept it.
	guessable := sha256.Sum256([]byte(unsubKeyContext + "|"))
	mac := hmac.New(sha256.New, guessable[:])
	mac.Write([]byte("victim@example.com"))
	forged := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
	if VerifyUnsubToken(DeriveUnsubKey(nil), "victim@example.com", forged) {
		t.Fatal("a token derived from the public constant verified")
	}
	// The point is that the key is never derived, not that this one value is
	// blacklisted: no short at-rest key may produce a usable key at all.
	if got := DeriveUnsubKey(nil); got != nil {
		t.Fatalf("an empty at-rest key still produced a %d-byte signing key", len(got))
	}
}

// TestUnsubTokenCarriesVersionAndExpiry (G7): the token used to be an eternal,
// unrevocable bearer capability over one address, sitting in every proxy log the
// mail passed through. Version and expiry are inside the signed material — there
// is no column to put them in — so neither can be edited by whoever holds the link.
func TestUnsubTokenCarriesVersionAndExpiry(t *testing.T) {
	key := DeriveUnsubKey(realKey)
	const addr = "guest@example.com"
	now := time.Now()
	tok := unsubToken(key, addr, now.Add(unsubTokenLife))

	if !strings.HasPrefix(tok, unsubTokenVersion+".") {
		t.Fatalf("token %q does not carry its version", tok)
	}
	if !verifyUnsubTokenAt(key, addr, tok, now) {
		t.Fatal("a fresh token does not verify")
	}
	if verifyUnsubTokenAt(key, "other@example.com", tok, now) {
		t.Fatal("a token verified for a different address")
	}
	if verifyUnsubTokenAt(key, addr, tok, now.Add(unsubTokenLife+time.Second)) {
		t.Fatal("an expired token still verifies: the capability is eternal again")
	}

	version, exp, mac, ok := splitUnsubToken(tok)
	if !ok {
		t.Fatalf("cannot split %q", tok)
	}
	// Extending the life by editing the token must fail: the expiry is signed.
	stretched := version + "." + "zzzzzzz" + "." + mac
	if verifyUnsubTokenAt(key, addr, stretched, now) {
		t.Fatal("an edited expiry verified")
	}
	// So must relabelling it as another version, in case a future version relaxes
	// something this one does not.
	if verifyUnsubTokenAt(key, addr, "9."+exp+"."+mac, now) {
		t.Fatal("a token relabelled to another version verified")
	}
	for _, junk := range []string{"", "...", "2.", "2..x", mac, "2." + exp} {
		if verifyUnsubTokenAt(key, addr, junk, now) {
			t.Fatalf("malformed token %q verified", junk)
		}
	}
}

// TestUnsubLegacyTokenSunset: v1 tokens are honoured until the sunset date because
// they are already in mail people hold, and a one-click unsubscribe button that
// fails gets answered with "report spam" instead — a complaint costs the whole
// domain's reputation. After the date they fail closed.
func TestUnsubLegacyTokenSunset(t *testing.T) {
	key := DeriveUnsubKey(realKey)
	const addr = "Guest@Example.com"
	legacy := legacyUnsubMAC(key, addr)

	before := unsubLegacySunset.Add(-24 * time.Hour)
	if !verifyUnsubTokenAt(key, "guest@example.com", legacy, before) {
		t.Fatal("a v1 token in someone's inbox stopped working before the sunset date")
	}
	if verifyUnsubTokenAt(key, "guest@example.com", legacy, unsubLegacySunset) {
		t.Fatal("a v1 token still verifies at the sunset date")
	}
	if verifyUnsubTokenAt(key, "someone-else@example.com", legacy, before) {
		t.Fatal("a v1 token verified for a different address")
	}
	if verifyUnsubTokenAt(DeriveUnsubKey([]byte(strings.Repeat("x", 32))), "guest@example.com", legacy, before) {
		t.Fatal("a v1 token verified under a different key")
	}
}

// TestUnsubscribeURLShape: the address is in the path so the endpoint needs no
// stored row, and the token is the only thing binding the link to that address.
func TestUnsubscribeURLShape(t *testing.T) {
	svc := New(nil, nil, "", "", "https://app.example.com", "", "", time.UTC, DeriveUnsubKey(realKey), nil)
	url := svc.UnsubscribeURL("Guest@Example.com")
	if !strings.HasPrefix(url, "https://app.example.com/u/") {
		t.Fatalf("unsubscribe URL = %q", url)
	}
	parts := strings.Split(strings.TrimPrefix(url, "https://app.example.com/u/"), "/")
	if len(parts) != 2 {
		t.Fatalf("unsubscribe path = %q, want <addr>/<token>", url)
	}
	addr, ok := DecodeUnsubAddress(parts[0])
	if !ok || addr != "guest@example.com" {
		t.Fatalf("decoded address = %q (ok=%v), want the normalised address", addr, ok)
	}
	if !VerifyUnsubToken(DeriveUnsubKey(realKey), addr, parts[1]) {
		t.Fatal("the token in a freshly built URL does not verify")
	}
}
