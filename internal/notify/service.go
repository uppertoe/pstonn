package notify

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/i18n"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/tenant"
)

// mailTenant is the tenant as a message sees it (see internal/i18n).
type mailTenant struct {
	Name, Short string
	Links       tenant.Links
	Terms       map[string]string
	// Loc is the tenant's own timezone when the resolver named one, else nil —
	// the zone a member's quiet hours are read in (quietDefer). nil keeps the
	// service's display zone, which is what every message used before tenants
	// had zones of their own.
	Loc *time.Location
}

// tenantOf resolves the tenant a message is about. tenantID names it exactly when
// the message concerns one permit or one session (the scheduler and the guest
// flows always have it); "" means an account-level message (invite, nudge,
// referral), which takes the owner's current tenant. Falls back to the default
// tenant when the resolver is unset or the id is unknown.
func (s *Service) tenantOf(ctx context.Context, owner, tenantID string) mailTenant {
	var c *tenant.Tenant
	var loc *time.Location
	if s.TenantFor != nil {
		if c = s.TenantFor(ctx, owner, tenantID); c != nil {
			loc = c.Location()
		}
	}
	if c == nil {
		c = tenant.Default()
	}
	return mailTenant{Name: c.Name, Short: c.Short, Links: c.Links,
		Terms: i18n.Default().For(i18n.DefaultLocale).Terms(c.Terms), Loc: loc}
}

// say renders a catalog message as text for a tenant with extra fields.
func say(c mailTenant, key string, extra map[string]any) string {
	data := map[string]any{"Tenant": c}
	for k, v := range extra {
		data[k] = v
	}
	out, err := i18n.Default().For(i18n.DefaultLocale).Text(key, data)
	if err != nil {
		alog.Infof("i18n: %v", err)
		return key
	}
	return out
}

// Service dispatches notifications according to each user's stored preferences.
type Service struct {
	// TenantFor resolves the tenant a message is about, for wording and links:
	// tenantID when given (a permit's or session's tenant), else the owner's
	// current tenant. nil means the default tenant. Set by main.
	TenantFor  func(ctx context.Context, owner, tenantID string) *tenant.Tenant
	store      *store.Store
	mail       *mailer.Mailer
	ntfyBase   string
	ntfyToken  string
	appURL     string         // public base URL, linked in messages
	adminEmail string         // operator alert address (systemic failures)
	adminTopic string         // operator alert ntfy topic
	loc        *time.Location // display timezone, for interpreting quiet-hours settings
	http       *http.Client
	// unsubKey signs unsubscribe links. Most recipients of our mail have no
	// account, so a stateless per-address token is the only opt-out they can have.
	unsubKey []byte
	// decideKey signs the no-sign-in approve/decline links in guest-request
	// emails (see decide.go). Separate from unsubKey so neither token can ever
	// verify as the other.
	decideKey []byte
	// displacedTo throttles the displaced-driver notice per recipient. That mail
	// goes to a third party who never signed up for anything, off a plate the
	// account holder chooses, so a plate flipping back and forth (or an owner
	// alternating two of them on purpose) would otherwise mail a stranger
	// indefinitely; the 15-minute outbox dedup only bounds the rate, not the total.
	displacedTo *sendLimiter
	// driverAddedTo throttles the "your car is on the permit" reassurance per
	// recipient. Roster changeovers fire this ~once a day per permit already; the
	// cap is a backstop against a plate flapping. 3/day leaves room for a driver
	// who covers two households.
	driverAddedTo *sendLimiter
	// failureTo and urgentFailureTo cap the apply-FAILURE notices one person can
	// receive in a day, across every permit they hear about. The scheduler's
	// durable key dedups an outcome per permit, but it remembers only the LAST
	// delivered key, so an outage whose outcome ping-pongs between families
	// (unreachable, then busy, then unreachable) could email on every capped retry.
	// A council outage must never become a stream of mail. Urgent notices (a
	// confirmed block, an expired sign-in: "change it yourself now") have their
	// own small budget so the soft notices cannot crowd them out.
	failureTo       *sendLimiter
	urgentFailureTo *sendLimiter
	// driverFailedTo caps the "your car couldn't be put on" driver notice per
	// recipient, like driverAddedTo: the driver has no account and no settings.
	driverFailedTo *sendLimiter
	// unrecorded holds bookkeeping the store refused for rows the drain has ALREADY
	// acted on. Touched only by the single RunOutbox goroutine, so it needs no lock.
	unrecorded map[int64]outboxUpdate
	// lastWriteAlert paces the operator alert for that condition, which otherwise
	// repeats on every 15-second tick for as long as the disk stays broken.
	lastWriteAlert time.Time
	// enqueueHook sees every message as composed, BEFORE the store hashes its
	// dedup key. Tests only: the golden files lock the plaintext key composition,
	// which the stored (digest) form cannot show. nil in production.
	enqueueHook func(store.OutboxItem)
	// applySeen remembers which members an inline NotifyApply reached, keyed by
	// the caller's outcome Key, so the retry of a PARTIAL delivery (one member
	// reached, another not) goes only to those who were missed. The scheduler's
	// durable per-permit key cannot say that — it is written only once everyone
	// is reached — and without this memory the reached member got the same notice
	// on every retry. In-memory: after a restart the worst case is one repeat to
	// someone already told. Guarded by applySeenMu; entries expire (applySeenTTL).
	applySeenMu sync.Mutex
	applySeen   map[string]time.Time
}

// applySeenTTL bounds how long a reached member is remembered. Far longer than
// any retry sequence (the scheduler stops once its durable key is written), and
// pruned as new entries land so the map tracks recent outcomes, not history.
const applySeenTTL = 24 * time.Hour

// reached reports whether the member was already reached for this outcome key.
func (s *Service) reached(seenKey string, now time.Time) bool {
	s.applySeenMu.Lock()
	defer s.applySeenMu.Unlock()
	t, ok := s.applySeen[seenKey]
	return ok && now.Sub(t) < applySeenTTL
}

// markReached records a member as reached for this outcome key, sweeping
// expired entries as it goes.
// forgetReached drops the reached-memory entries of a completed delivery.
func (s *Service) forgetReached(keys []string) {
	if len(keys) == 0 {
		return
	}
	s.applySeenMu.Lock()
	defer s.applySeenMu.Unlock()
	for _, k := range keys {
		delete(s.applySeen, k)
	}
}

func (s *Service) markReached(seenKey string, now time.Time) {
	s.applySeenMu.Lock()
	defer s.applySeenMu.Unlock()
	if s.applySeen == nil {
		s.applySeen = map[string]time.Time{} // literal-constructed test services
	}
	for k, t := range s.applySeen {
		if now.Sub(t) >= applySeenTTL {
			delete(s.applySeen, k)
		}
	}
	s.applySeen[seenKey] = now
}

// New builds a Service. mail may be nil (email disabled); ntfyBase may be empty
// (push disabled). adminEmail/adminTopic receive operator alerts (either may be
// empty).
func New(st *store.Store, m *mailer.Mailer, ntfyBase, ntfyToken, appURL, adminEmail, adminTopic string, loc *time.Location, unsubKey, decideKey []byte) *Service {
	if loc == nil {
		loc = time.Local
	}
	return &Service{
		store:      st,
		mail:       m,
		ntfyBase:   strings.TrimRight(ntfyBase, "/"),
		ntfyToken:  ntfyToken,
		appURL:     strings.TrimRight(appURL, "/"),
		adminEmail: strings.TrimSpace(adminEmail),
		adminTopic: strings.TrimSpace(adminTopic),
		loc:        loc,
		http:       &http.Client{Timeout: 10 * time.Second},
		unsubKey:   unsubKey,
		decideKey:  decideKey,
		// Roughly three times what a real recipient sees: a guest whose car is
		// displaced hears about it when the booking ends, so once or twice a day. Far
		// below what makes an unsolicited mail stream feel like harassment, and well
		// under the rate that earns a spam complaint against the whole domain.
		displacedTo:   newSendLimiter(6, 24*time.Hour),
		driverAddedTo: newSendLimiter(3, 24*time.Hour),
		// Three soft failure notices a day is already one more than a person can
		// act on; two urgent ones covers "act now" and its escalation.
		failureTo:       newSendLimiter(3, 24*time.Hour),
		urgentFailureTo: newSendLimiter(2, 24*time.Hour),
		driverFailedTo:  newSendLimiter(2, 24*time.Hour),
		unrecorded:      map[int64]outboxUpdate{},
	}
}

// memberPref pairs an account member with their OWN notification preference, so a
// change notifies each person by the channels they chose for themselves.
type memberPref struct {
	email string
	pref  store.NotifyPref
}

// accountDeliveries returns every member of an account (owner plus any
// secondaries), each paired with their own notify_pref. Preferences are
// per-person: a secondary turning their email off must not silence the primary,
// so we never fold the account into one shared preference. A member with no row
// yet gets the defaults (email on).
func (s *Service) accountDeliveries(ctx context.Context, owner string) ([]memberPref, error) {
	emails, err := s.store.AccountEmails(ctx, owner)
	if err != nil {
		return nil, err
	}
	out := make([]memberPref, 0, len(emails))
	for _, e := range emails {
		p, err := s.store.GetNotifyPref(ctx, e)
		if err != nil {
			return nil, err
		}
		out = append(out, memberPref{email: e, pref: p})
	}
	return out, nil
}

// Enabled reports whether any channel is available at all.
func (s *Service) Enabled() bool { return s.mail.Enabled() || s.ntfyBase != "" }

// EmailAvailable / NtfyAvailable report which channels the operator configured
// (so the UI can hide options that can't work).
func (s *Service) EmailAvailable() bool { return s.mail.Enabled() }
func (s *Service) NtfyAvailable() bool  { return s.ntfyBase != "" }

// NtfyBase is the public ntfy server URL, shown in the UI so users can subscribe.
func (s *Service) NtfyBase() string { return s.ntfyBase }

// AdminConfigured reports whether any operator alert channel is set up.
func (s *Service) AdminConfigured() bool {
	return (s.adminEmail != "" && s.mail.Enabled()) || (s.adminTopic != "" && s.ntfyBase != "")
}

// MaxQuietHours caps the quiet-hours window. The hold applies to failure
// notices too (the transient kind), and an uncapped window let a 07:00→06:00
// setting park "your permit couldn't be updated" for 23 hours — a full day of
// visitors on the wrong plate behind one settings choice. Half a day covers
// every real overnight window while bounding the worst case. Enforced both at
// save (settings) and here at delivery, so a stored wider window from before
// the cap still cannot hold a message past it.
const MaxQuietHours = 12

// quietDefer decides when a notification for this member should actually be
// delivered. Members can set quiet hours (default 22:00–06:00 local): a message
// generated inside that window is held and released at the window's end (so a
// midnight roster change lands as a 6am confirmation, not a 12:01am ping).
// Messages generated outside the window — and all messages when quiet hours are
// off (QuietFrom == QuietUntil) — deliver immediately (zero time). now is passed
// in for testability.
//
// loc is the zone "22:00" is read in: the tenant's (mailTenant.Loc), because a
// household's night is the night where their permit is, and the service's single
// display zone is wrong for every tenant outside it. nil falls back to that
// display zone — the behaviour before tenants carried zones of their own.
func (s *Service) quietDefer(pref store.NotifyPref, now time.Time, loc *time.Location) time.Time {
	from, until := pref.QuietFrom, pref.QuietUntil
	if from == until || from < 0 || from > 23 || until < 0 || until > 23 {
		return time.Time{} // disabled or malformed → immediate
	}
	if span := ((until - from) + 24) % 24; span > MaxQuietHours {
		until = (from + MaxQuietHours) % 24
	}
	if loc == nil {
		loc = s.loc
	}
	lt := now.In(loc)
	h := lt.Hour()
	var inQuiet bool
	if from < until {
		inQuiet = h >= from && h < until
	} else { // window wraps midnight, e.g. 22..6
		inQuiet = h >= from || h < until
	}
	if !inQuiet {
		return time.Time{}
	}
	target := time.Date(lt.Year(), lt.Month(), lt.Day(), until, 0, 0, 0, loc)
	if !target.After(lt) {
		target = target.AddDate(0, 0, 1)
	}
	return target
}
