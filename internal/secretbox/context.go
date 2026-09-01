package secretbox

// The context strings below are the ONLY ones the app uses, kept together so a seal
// site and its open site cannot drift apart — a mismatch there is not a compile
// error, it is a blob that silently opens as "legacy" forever and never gains its
// binding. Each one names whose secret it is and what it is for, which is exactly
// the pair that was missing.
//
// A purpose prefix stops a value moving BETWEEN columns (the tenant password into a
// guest token row, where the door-QR page would print it). The owner stops it moving
// BETWEEN households. The tenant stops it moving BETWEEN COUNCILS within one
// household: the session row is keyed (owner, council_id), so one account can hold
// several sessions, and without the tenant in the binding a row swap would replay
// one council's saved password at another council's login page. Nothing here is
// secret; it is all recoverable from the row being read, which is the requirement
// for associated data.
//
// Two spellings per tenant secret, for the same migration reason the unbound
// fallback exists (see Box.OpenCtx): every blob in production was sealed under the
// owner-only form. The ...For(owner, tenant) form is what new writes use; the
// owner-only form is what an open falls back to, reporting legacy so the caller
// re-seals. A tenant of "" collapses to the owner-only form, so a call site that
// has not yet learned its tenant keeps working unchanged.

// TenantCookie binds a stored tenant session cookie to its account (owner-only
// spelling; see TenantCookieFor).
func TenantCookie(owner string) string { return "council-cookie:" + owner }

// TenantCookieFor binds a stored tenant session cookie to its account AND the
// council it is a session with.
func TenantCookieFor(owner, tenant string) string { return withTenant("council-cookie", owner, tenant) }

// TenantToken binds a cached tenant API access token to its account (owner-only
// spelling; see TenantTokenFor).
func TenantToken(owner string) string { return "council-token:" + owner }

// TenantTokenFor is TenantToken bound to the council as well.
func TenantTokenFor(owner, tenant string) string { return withTenant("council-token", owner, tenant) }

// TenantPassword binds an opt-in saved tenant password to its account. This is the
// most sensitive value the app stores and the one the door-QR page would have
// displayed had a blob been moved into a guest_token row. Owner-only spelling; see
// TenantPasswordFor.
func TenantPassword(owner string) string { return "council-password:" + owner }

// TenantPasswordFor is TenantPassword bound to the council as well — the one that
// matters most, since a password sealed for one council must never be replayed at
// another's portal.
func TenantPasswordFor(owner, tenant string) string {
	return withTenant("council-password", owner, tenant)
}

// GuestToken binds a reprintable guest-pass token to the account that minted it.
// Covers both the on-screen visitor QR and the printed door QR: they are the same
// kind of secret, and moving one to the other is within a single household, so it
// discloses that household nothing it does not already own. Not tenant-bound: a
// grant belongs to a permit, and the permit row already names its council.
func GuestToken(owner string) string { return "guest-token:" + owner }

// NtfyConfirm binds the token carried by a test push's Confirm button. The
// plaintext names the owner and topic itself, and the button posts back from the
// phone with no session, so the context cannot depend on the owner — the purpose
// alone is what keeps this blob from opening as anything else (or anything else
// from opening as a confirmation).
func NtfyConfirm() string { return "ntfy-confirm" }

// withTenant lays out purpose:tenant:owner. The tenant goes BEFORE the owner
// because an owner is an email address, which may legally contain a colon, while a
// tenant id is a registry slug that never does — so the string parses one way only.
func withTenant(purpose, owner, tenant string) string {
	if tenant == "" {
		return purpose + ":" + owner
	}
	return purpose + ":" + tenant + ":" + owner
}
