// Package provider is the contract between p.stonn's core (scheduling, guests,
// households, notifications) and a permit backend. A Provider owns one portal's
// protocol — how to sign in, keep a session alive, list permits, read and write
// the vehicle — and nothing else: it is stateless with respect to app users,
// speaks in terms of an opaque Session it is handed, and reports failures only
// through the typed vocabulary in this package. Everything per-owner (sealing and
// persisting sessions, caching, backoff, the fleet breaker, saved passwords) lives
// once in the generic client (internal/parking) and is shared by every provider.
//
// Wording is deliberately absent here. A provider never composes a sentence for a
// person: it returns a kind, an operation and an optional tenant-supplied detail,
// and the UI/notification layer chooses words for them (see the i18n section of
// docs/tenant-connections.md). That is what lets a second backend be a genuine
// test of the architecture rather than a fork of the application.
package provider

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Session is a provider's opaque, provider-defined session material (for the
// Orikan portal: the IdentityServer cookie plus a cached access token). The generic
// client seals and persists it without interpreting it, and passes it back by
// pointer so a provider can rotate it in place; a changed value is re-persisted.
type Session []byte

// Credentials is what a person supplies to sign in. Today every provider is
// password-based; Capabilities.LoginKind says which fields a provider reads.
type Credentials struct {
	Username string
	Password string
}

// PermitRef identifies a permit to act on: the provider's own id for it.
type PermitRef struct {
	ID string
}

// Permit is one permit on the account as the provider reports it.
type Permit struct {
	CouncilPermitID  string // the provider's permit id (Orikan: PKPermitID)
	PermitTypeID     string // the provider's permit-type id
	PermitNumber     string // the human permit number, e.g. "VPP24714"
	PermitType       string // the permit type's display name, e.g. "(A) 1st Visitor Permit"
	Status           string // the provider's status word, e.g. "Granted"
	CurrentRego      string // the plate currently on the permit ("" = none)
	StartDate        time.Time
	EndDate          time.Time
	CanChangeVehicle bool // the holder may change the vehicle (per permit type — tenant config)
	IsCoHolder       bool
}

// Vehicle is what is on a permit right now. Registration "" means the permit
// genuinely has no vehicle (a provider must not report "" for a shape it did not
// understand — that is FailUnexpected).
type Vehicle struct {
	Registration string
}

// Capabilities declares what a provider supports, so the core can adapt rather
// than assume: hide a button, skip keep-warm, choose a login flow.
type Capabilities struct {
	// CanClearVehicle: the permit can be left with no vehicle at all.
	CanClearVehicle bool
	// SupportsRefresh: Refresh keeps a session alive without credentials.
	SupportsRefresh bool
	// NeedsKeepWarm: an idle session lapses unless refreshed within IdleWindow, so
	// the scheduler must touch it periodically (Orikan's sliding cookie). A provider
	// with durable refresh tokens sets this false.
	NeedsKeepWarm bool
	// IdleWindow is the provider's estimated idle timeout when NeedsKeepWarm.
	IdleWindow time.Duration
	// SupportsExpiry: Permit.EndDate is meaningful.
	SupportsExpiry bool
	// LoginKind names the credential shape: "password" (username + password).
	LoginKind string
}

// Provider is one permit backend. Implementations must be safe for concurrent use;
// the generic client serialises calls per owner, so a Session pointer is never
// shared between concurrent calls.
type Provider interface {
	// ID is the stable connector name ("orikan-ssp", "fake").
	ID() string
	Capabilities() Capabilities
	// Login signs in with credentials and returns fresh session material. It
	// returns ErrLoginRejected when the portal accepted the request but issued no
	// session (wrong credentials), and never stores the credentials.
	Login(ctx context.Context, creds Credentials) (Session, error)
	// Refresh keeps the session alive, rotating it in place if the portal does.
	// ErrSessionExpired means the session is no longer accepted.
	Refresh(ctx context.Context, s *Session) error
	// ListPermits returns the account's permits and the total the portal claims
	// it holds; len(permits) < total means the list is a page, not the account.
	ListPermits(ctx context.Context, s *Session) (permits []Permit, total int, err error)
	CurrentVehicle(ctx context.Context, s *Session, p PermitRef) (Vehicle, error)
	SetVehicle(ctx context.Context, s *Session, p PermitRef, registration string) error
	ClearVehicle(ctx context.Context, s *Session, p PermitRef) error
}

// ---- errors ----

// Sentinels. A provider returns these (possibly wrapped) and nothing worded; the
// generic client and the core act on them by identity.
var (
	// ErrNotLinked: the app user has no stored session. Raised by the generic
	// client, never by a provider.
	ErrNotLinked = errors.New("provider: account not linked")
	// ErrSessionExpired: the session is no longer accepted; a re-login is required.
	ErrSessionExpired = errors.New("provider: session expired")
	// ErrNoSavedPassword: an auto-reconnect was attempted with nothing to use.
	ErrNoSavedPassword = errors.New("provider: no saved password")
	// ErrLoginRejected: the portal answered the login but issued no session — the
	// credentials are wrong (as opposed to a fault, which is any other error).
	ErrLoginRejected = errors.New("provider: login rejected")
	// ErrLoginFormUnrecognised: the sign-in page was fetched but is not a form this
	// provider knows how to submit. Says nothing about the password; needs an
	// operator to look at the portal.
	ErrLoginFormUnrecognised = errors.New("provider: sign-in page not recognised")
	// ErrLoginOffHost: the flow was asked to send the password somewhere the
	// configuration never named. A security event; the credentials were not sent.
	ErrLoginOffHost = errors.New("provider: sign-in points off-host")
	// ErrNotCaptured: the operation's wire shape is unknown for this provider.
	ErrNotCaptured = errors.New("provider: endpoint not captured")
	// ErrUnavailable: the portal is pushing back (rate-limited, blocked, down) or
	// the owner is in a backoff. Transient; do not retry immediately. Usually
	// carried by *Unavailable.
	ErrUnavailable = errors.New("provider: portal unavailable")
	// ErrPermitListPartial: the portal returned fewer permits than it reported.
	ErrPermitListPartial = errors.New("provider: permit list partial")
	// ErrPermitInactive: the portal refuses the permit as no longer active.
	ErrPermitInactive = errors.New("provider: permit inactive")
	// ErrUnsupported: the provider's Capabilities exclude this operation.
	ErrUnsupported = errors.New("provider: operation not supported")
)

// Unavailable is ErrUnavailable with the push-back's particulars, so the generic
// client can honour Retry-After, tally the surface and open the fleet breaker.
type Unavailable struct {
	RetryAfter  time.Duration
	Status      int
	Surface     Surface
	ContentType string
	Ref         string // the edge's correlation id (Azure Front Door: X-Azure-Ref)
}

func (u *Unavailable) Error() string {
	return fmt.Sprintf("%v: %s returned %d", ErrUnavailable, u.Surface, u.Status)
}
func (u *Unavailable) Unwrap() error { return ErrUnavailable }

// Op names what a call was doing when it failed. It is an identifier, not a
// sentence: the notification layer maps it to words.
type Op int

const (
	OpUnknown Op = iota
	OpLogin
	OpRefresh
	OpListPermits
	OpReadVehicle
	OpSetVehicle
	OpAddVehicle
	OpClearVehicle
)

var opNames = [...]string{"unknown", "login", "refresh", "list-permits", "read-vehicle", "set-vehicle", "add-vehicle", "clear-vehicle"}

// String is the stable identifier used in logs and catalog keys.
func (o Op) String() string {
	if int(o) < len(opNames) {
		return opNames[o]
	}
	return "unknown"
}

// FailureKind classifies WHY an operation failed, so the core can decide between
// a quiet retry and asking the user to act.
type FailureKind int

const (
	// FailTransient: a network error or a 5xx. A retry is likely to succeed.
	FailTransient FailureKind = iota
	// FailRejected: the portal refused (a 4xx, a permit that cannot be edited).
	// It will not fix itself; the user needs to check or act.
	FailRejected
	// FailUnexpected: a response this provider could not understand — possibly a
	// glitch, possibly a changed API (an operator alert in bulk).
	FailUnexpected
)

// Error is a classified failure. Detail is tenant-supplied text (already
// sanitised by the provider) that may be shown to the person because it is the
// only thing that says what to fix ("Vehicle Registration has invalid pattern");
// "" when there is none. Err is the cause, for logs.
type Error struct {
	Kind   FailureKind
	Op     Op
	Detail string
	Err    error
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("provider: %s: %s: %v", e.Op, e.Detail, e.Err)
	}
	return fmt.Sprintf("provider: %s: %v", e.Op, e.Err)
}
func (e *Error) Unwrap() error { return e.Err }

// Fail builds a classified error.
func Fail(kind FailureKind, op Op, err error) error {
	return &Error{Kind: kind, Op: op, Err: err}
}

// FailDetail builds a classified error carrying tenant-supplied detail.
func FailDetail(kind FailureKind, op Op, detail string, err error) error {
	return &Error{Kind: kind, Op: op, Detail: detail, Err: err}
}

// FailureOf extracts the classification. Anything that is not an *Error is
// FailTransient (retry, don't alarm): an unclassified error is more likely a
// glitch than a permanent refusal.
func FailureOf(err error) (FailureKind, Op) {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind, e.Op
	}
	return FailTransient, OpUnknown
}

// DetailOf returns the tenant-supplied detail on a classified error, or "".
func DetailOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Detail
	}
	return ""
}

// ---- request surfaces ----

// Surface classifies an outbound request for traffic accounting and the login
// sub-limit. Providers tag each request's context; the generic transport reads it.
type Surface string

const (
	SurfaceLogin Surface = "login" // the credential flow itself (form GET, password POST)
	SurfaceAuth  Surface = "auth"  // token/session maintenance (authorize, token exchange)
	SurfaceAPI   Surface = "api"   // the permit API
	SurfaceOther Surface = "other"
)

type surfaceKey struct{}

// WithSurface tags a request context with its surface.
func WithSurface(ctx context.Context, s Surface) context.Context {
	return context.WithValue(ctx, surfaceKey{}, s)
}

// SurfaceOf reads the surface a request was tagged with (SurfaceOther if none).
func SurfaceOf(ctx context.Context) Surface {
	if s, ok := ctx.Value(surfaceKey{}).(Surface); ok && s != "" {
		return s
	}
	return SurfaceOther
}
