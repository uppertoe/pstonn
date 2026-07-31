package notify

import (
	"strings"
	"testing"
	"time"
)

// TestNeutraliseLinks (G2): the permit label is owner-typed free text that ends up
// in a DKIM-signed email to any address the owner names, and the HTML alternative
// turns bare URLs into real links. A legitimate label must survive untouched; a URL
// must not arrive clickable.
func TestNeutraliseLinks(t *testing.T) {
	for _, keep := range []string{
		"Nanny", "12 Example St", "Flat 3 / 400 Example Rd", "Mum's spot (rear)", "café permit",
	} {
		if got := neutraliseLinks(keep); got != keep {
			t.Errorf("neutraliseLinks(%q) = %q, want it unchanged", keep, got)
		}
	}
	for _, hostile := range []string{
		"https://evil.example/steal",
		"HTTP://evil.example",
		"permit http://evil.example/x now",
		"see https://evil.example/a and https://evil.example/b",
	} {
		got := neutraliseLinks(hostile)
		if strings.Contains(strings.ToLower(got), "http") {
			t.Errorf("neutraliseLinks(%q) = %q, still carries a URL", hostile, got)
		}
	}
}

// TestDisplacedDriverPerRecipientCap (G3): this mail goes to a third party with no
// account and no way to have asked for it. The dedup key includes the plate, so
// alternating two plates produces a fresh key every time — only a per-recipient cap
// bounds the total, the way every other path that mails a merely-named address does.
func TestDisplacedDriverPerRecipientCap(t *testing.T) {
	l := newSendLimiter(6, 24*time.Hour)
	const driver = "driver@example.com"
	for i := 0; i < 6; i++ {
		if !l.allow(driver) {
			t.Fatalf("notice %d refused, want the first 6 through", i+1)
		}
	}
	if l.allow(driver) {
		t.Fatal("the 7th notice to one recipient in a day was allowed")
	}
	// The cap is per recipient: one busy household must not silence another's.
	if !l.allow("someone-else@example.com") {
		t.Fatal("one recipient's cap blocked a different recipient")
	}
}
