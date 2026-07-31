package secretbox

// The context strings below are the ONLY ones the app uses, kept together so a seal
// site and its open site cannot drift apart — a mismatch there is not a compile
// error, it is a blob that silently opens as "legacy" forever and never gains its
// binding. Each one names whose secret it is and what it is for, which is exactly
// the pair that was missing.
//
// A purpose prefix stops a value moving BETWEEN columns (the council password into a
// guest token row, where the door-QR page would print it). The owner stops it moving
// BETWEEN households. Nothing here is secret; it is all recoverable from the row
// being read, which is the requirement for associated data.

// CouncilCookie binds a stored council session cookie to its account.
func CouncilCookie(owner string) string { return "council-cookie:" + owner }

// CouncilToken binds a cached council API access token to its account.
func CouncilToken(owner string) string { return "council-token:" + owner }

// CouncilPassword binds an opt-in saved council password to its account. This is the
// most sensitive value the app stores and the one the door-QR page would have
// displayed had a blob been moved into a guest_token row.
func CouncilPassword(owner string) string { return "council-password:" + owner }

// GuestToken binds a reprintable guest-pass token to the account that minted it.
// Covers both the on-screen visitor QR and the printed door QR: they are the same
// kind of secret, and moving one to the other is within a single household, so it
// discloses that household nothing it does not already own.
func GuestToken(owner string) string { return "guest-token:" + owner }
