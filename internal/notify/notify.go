// Package notify sends per-user change notifications ("reassurance") over the
// user's chosen channels (email and/or a self-hosted ntfy server) and operator
// alerts for systemic failures. A missed permit change can mean a fine, so each
// applied change and failure is surfaced to the permit owner; NotifyApply reports
// how many channels accepted the message so the scheduler can retry and escalate
// to the operator (NotifyAdmin) when a user cannot be reached, rather than
// failing silently.
package notify

import "errors"

// Provenance reasons. Each user-facing mail must say why THIS address received
// it: several recipient classes (a guest handed a pass, a driver whose car came
// off a permit) never signed up for anything and are owed an explanation and a
// way out.
const (
	reasonAccount  = "this address manages, or shares access to, a p.stonn account that schedules a visitor parking permit"
	reasonGuest    = "someone shared their visitor parking permit with you by email"
	reasonInvite   = "someone gave this address shared access to their p.stonn account"
	reasonDisplace = "this address is the contact for a car that was on a visitor permit"
	reasonDriverOn = "this address is the contact for a car put on a visitor parking permit"
	reasonTest     = "you asked p.stonn to send a test notification"
	reasonOnboard  = "you signed up for p.stonn with it but haven't connected a council account yet"
	reasonReferral = "someone who uses p.stonn asked us to tell you about it"
)

// The tenant's own account pages, deep-linked wherever p.stonn tells someone
// their remedy lives at the tenant. Bare paths on purpose: the portal decorates
// these with one-time OIDC state (nonce, PKCE challenge) that would be stale in
// a stored link, and both pages work without it.

// ErrSuppressed reports that an address is on the suppression list, so nothing
// was sent. It is a permanent condition, not a delivery failure: callers must
// not retry, and the outbox treats it as terminal.
var ErrSuppressed = errors.New("address is suppressed (previous bounce or complaint)")
