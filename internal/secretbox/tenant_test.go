package secretbox

import "testing"

// The session row is keyed (owner, council_id): one household can hold a session
// — and a saved password — with more than one council. Owner-only binding let a
// row swap move one council's password ciphertext into another council's row,
// where the auto-reconnect would replay it at the wrong portal.
func TestCiphertextCannotMoveBetweenCouncils(t *testing.T) {
	b := testBox(t, 1)
	const owner = "household@example.com"
	sealed, err := b.SealCtx(TenantPasswordFor(owner, "stonnington"), "the-stonnington-password")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if pt, legacy, err := b.OpenCtxAny(sealed, TenantPasswordFor(owner, "banyule"), TenantPassword(owner)); err == nil {
		t.Fatalf("a password sealed for one council opened under another (legacy=%v, %q)", legacy, pt)
	}
	// Nor as another purpose for the same council, nor for another household.
	for _, ctx := range []string{TenantCookieFor(owner, "stonnington"), TenantTokenFor(owner, "stonnington"), TenantPasswordFor("other@example.com", "stonnington")} {
		if _, _, err := b.OpenCtxAny(sealed, ctx); err == nil {
			t.Errorf("opened under %q", ctx)
		}
	}
	got, legacy, err := b.OpenCtxAny(sealed, TenantPasswordFor(owner, "stonnington"), TenantPassword(owner))
	if err != nil || got != "the-stonnington-password" || legacy {
		t.Fatalf("own context: %q legacy=%v %v", got, legacy, err)
	}
}

// Every blob in production was sealed under the owner-only spelling. It must
// still open under the tenant-bound chain — reported legacy, so the caller
// re-seals — and after that re-seal the owner-only spelling no longer opens it.
func TestOwnerOnlyCiphertextOpensAsLegacyAndReseals(t *testing.T) {
	b := testBox(t, 1)
	const owner = "household@example.com"
	old, err := b.SealCtx(TenantCookie(owner), "Permits.IDM.Identity=live")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	pt, legacy, err := b.OpenCtxAny(old, TenantCookieFor(owner, "stonnington"), TenantCookie(owner))
	if err != nil || pt != "Permits.IDM.Identity=live" {
		t.Fatalf("owner-only blob must still open: %q %v", pt, err)
	}
	if !legacy {
		t.Fatal("an owner-only blob must be reported legacy, or it is never re-sealed")
	}
	// Plain OpenCtx with the owner-only context keeps working for call sites that
	// have not moved yet (and reports it as current, since that IS its context).
	if _, legacy, err := b.OpenCtx(TenantCookie(owner), old); err != nil || legacy {
		t.Fatalf("owner-only OpenCtx: legacy=%v %v", legacy, err)
	}
	rebound, err := b.SealCtx(TenantCookieFor(owner, "stonnington"), pt)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.OpenCtx(TenantCookie(owner), rebound); err == nil {
		t.Fatal("after re-sealing, the owner-only spelling still opens the blob: the tenant binding did not take")
	}
	if _, legacy, err := b.OpenCtxAny(rebound, TenantCookieFor(owner, "stonnington"), TenantCookie(owner)); err != nil || legacy {
		t.Fatalf("re-sealed blob should open current: legacy=%v %v", legacy, err)
	}
	// The pre-binding unbound blob is still the last fallback, still legacy.
	unbound, _ := b.Seal("very-old")
	if pt, legacy, err := b.OpenCtxAny(unbound, TenantCookieFor(owner, "stonnington"), TenantCookie(owner)); err != nil || pt != "very-old" || !legacy {
		t.Fatalf("unbound fallback: %q legacy=%v %v", pt, legacy, err)
	}
}

// An unknown tenant collapses to the owner-only spelling, so a call site that has
// no tenant yet seals exactly what it always did — and the spellings are distinct
// for every (purpose, tenant) pair.
func TestTenantContextsCollapseAndStayDistinct(t *testing.T) {
	const owner = "a@example.com"
	if TenantCookieFor(owner, "") != TenantCookie(owner) || TenantTokenFor(owner, "") != TenantToken(owner) || TenantPasswordFor(owner, "") != TenantPassword(owner) {
		t.Fatal("an empty tenant must collapse to the owner-only spelling")
	}
	seen := map[string]bool{}
	for _, c := range []string{
		TenantCookie(owner), TenantToken(owner), TenantPassword(owner), GuestToken(owner),
		TenantCookieFor(owner, "stonnington"), TenantTokenFor(owner, "stonnington"), TenantPasswordFor(owner, "stonnington"),
		TenantCookieFor(owner, "banyule"), TenantTokenFor(owner, "banyule"), TenantPasswordFor(owner, "banyule"),
	} {
		if seen[c] {
			t.Fatalf("duplicate context %q", c)
		}
		seen[c] = true
	}
	if _, _, err := testBox(t, 1).OpenCtxAny("AAAA"); err == nil {
		t.Fatal("OpenCtxAny with no context must refuse rather than bind nothing")
	}
}
