// Package notify sends per-user change notifications ("reassurance") over the
// user's chosen channels (email and/or a self-hosted ntfy server) and operator
// alerts for systemic failures. A missed permit change can mean a fine, so each
// applied change and failure is surfaced to the permit owner; NotifyApply reports
// how many channels accepted the message so the scheduler can retry and escalate
// to the operator (NotifyAdmin) when a user cannot be reached, rather than
// failing silently.
package notify

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/i18n"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/tenant"
)

// mailTenant is the tenant as a message sees it (see internal/i18n).
type mailTenant struct {
	Name, Short string
	Links       tenant.Links
	Terms       map[string]string
}

// tenantOf resolves the tenant for an account (owner), or the default tenant
// when the resolver is unset or the account is unknown.
func (s *Service) tenantOf(ctx context.Context, owner string) mailTenant {
	var c *tenant.Tenant
	if s.TenantFor != nil {
		c = s.TenantFor(ctx, owner)
	}
	if c == nil {
		c = tenant.Default()
	}
	return mailTenant{Name: c.Name, Short: c.Short, Links: c.Links,
		Terms: i18n.Default().For(i18n.DefaultLocale).Terms(c.Terms)}
}

// say renders a catalog message as text for a tenant with extra fields.
func say(c mailTenant, key string, extra map[string]any) string {
	data := map[string]any{"Tenant": c}
	for k, v := range extra {
		data[k] = v
	}
	out, err := i18n.Default().For(i18n.DefaultLocale).Text(key, data)
	if err != nil {
		log.Printf("i18n: %v", err)
		return key
	}
	return out
}

// Service dispatches notifications according to each user's stored preferences.
type Service struct {
	// TenantFor resolves an account's tenant, for wording and links; nil means
	// the default tenant. Set by main.
	TenantFor  func(ctx context.Context, owner string) *tenant.Tenant
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
	// unrecorded holds bookkeeping the store refused for rows the drain has ALREADY
	// acted on. Touched only by the single RunOutbox goroutine, so it needs no lock.
	unrecorded map[int64]outboxUpdate
	// lastWriteAlert paces the operator alert for that condition, which otherwise
	// repeats on every 15-second tick for as long as the disk stays broken.
	lastWriteAlert time.Time
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
		displacedTo: newSendLimiter(6, 24*time.Hour),
		unrecorded:  map[int64]outboxUpdate{},
	}
}

// RedactEmail and redactEmails are thin wrappers over the shared redact package,
// kept so notify's many existing callers don't churn. The reasoning (logs are
// the leakiest surface, the full address stays in the DB) now lives in redact.
func RedactEmail(a string) string       { return redact.Email(a) }
func redactEmails(list []string) string { return redact.Emails(list) }

// neutraliseLinks strips whole URLs out of owner-supplied free text (a permit
// label) before it reaches mail we send to people who never opted in.
//
// The label is the owner's own text, capped at 40 characters and shown in the
// app, but a guest-pass email is DKIM-signed by our domain and sent to any
// address the owner types. The HTML alternative turns bare URLs in the body into
// real links (mailer.linkify), so without this an account is a machine for
// mailing a clickable attacker link from a domain with our reputation — and the
// recipient's spam report lands as a complaint, which is the one suppression that
// is never pruned and never user-clearable. Removing just the URL keeps every
// legitimate label ("Nanny", "12 Example St") completely intact.
func neutraliseLinks(label string) string {
	return strings.TrimSpace(linkRun.ReplaceAllString(label, "(link removed)"))
}

// linkRun matches what the mail layer would turn into a clickable link, and must
// be at least as broad as the linkifier (mailer.inlineURL, `https?://[^\s<>()]+`)
// or a URL slips past here and is still hyperlinked there. It deliberately has NO
// leading word boundary: `\bhttps` does not anchor inside `2https://evil` (the
// boundary the linkifier does not require either), so a label like "2https://evil"
// would otherwise survive the strip and reach the recipient as a live link. `\S*`
// is strictly broader than the linkifier's character class, so nothing it would
// wrap can escape this.
var linkRun = regexp.MustCompile(`(?i)https?://\S*`)

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
func (s *Service) quietDefer(pref store.NotifyPref, now time.Time) time.Time {
	from, until := pref.QuietFrom, pref.QuietUntil
	if from == until || from < 0 || from > 23 || until < 0 || until > 23 {
		return time.Time{} // disabled or malformed → immediate
	}
	if span := ((until - from) + 24) % 24; span > MaxQuietHours {
		until = (from + MaxQuietHours) % 24
	}
	lt := now.In(s.loc)
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
	target := time.Date(lt.Year(), lt.Month(), lt.Day(), until, 0, 0, 0, s.loc)
	if !target.After(lt) {
		target = target.AddDate(0, 0, 1)
	}
	return target
}

// AdminConfigured reports whether any operator alert channel is set up.
func (s *Service) AdminConfigured() bool {
	return (s.adminEmail != "" && s.mail.Enabled()) || (s.adminTopic != "" && s.ntfyBase != "")
}

// Provenance reasons. Each user-facing mail must say why THIS address received
// it: several recipient classes (a guest handed a pass, a driver whose car came
// off a permit) never signed up for anything and are owed an explanation and a
// way out.
const (
	reasonAccount  = "this address manages, or shares access to, a p.stonn account that schedules a visitor parking permit"
	reasonGuest    = "someone shared their visitor parking permit with you by email"
	reasonInvite   = "someone gave this address shared access to their p.stonn account"
	reasonDisplace = "this address is the contact for a car that was on a visitor permit"
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

// sendEmail is the single choke point for user-facing email. It refuses to send
// to an address the provider has told us is dead or that complained, and it
// records a permanent SMTP refusal as a new suppression so the next send skips
// it rather than repeating the damage.
//
// Operator alerts deliberately do NOT go through here: if the operator's own
// address bounces we still want every future attempt made (and the failure
// logged), rather than the app quietly muting its own alarm channel.
func (s *Service) sendEmail(ctx context.Context, to, subject, body, reason string) error {
	return s.sendEmailWith(ctx, to, subject, body, reason, false)
}

// sendEmailCritical is sendEmail for safety-critical mail: messages whose miss
// can cost the household a fine (an action-needed apply failure, a re-link
// prompt, a stalled reconnect, a disconnection). A recipient's own unsubscribe
// does not stop these — unsubscribing opts out of the routine notification
// stream, not of being told their permit is no longer being managed, and the
// unsubscribe page says exactly that. A bounce or a complaint still blocks:
// those addresses are dead or asked-us-to-stop-via-their-provider, and mailing
// them anyway damages deliverability for every user of the sending domain.
// (Outbox rows never need this: an action-needed outcome bypasses the
// quiet-hours hold and is sent inline, so queued rows are routine by
// construction.)
func (s *Service) sendEmailCritical(ctx context.Context, to, subject, body, reason string) error {
	return s.sendEmailWith(ctx, to, subject, body, reason, true)
}

func (s *Service) sendEmailWith(ctx context.Context, to, subject, body, reason string, critical bool) error {
	return s.sendEmailAs(ctx, to, to, subject, body, reason, critical)
}

// sendEmailAs is sendEmailWith for a recipient whose tenant is that of
// tenantOwner (a guest or invitee has no account; the owner who reached them does).
func (s *Service) sendEmailAs(ctx context.Context, tenantOwner, to, subject, body, reason string, critical bool) error {
	if !s.mail.Enabled() {
		return nil
	}
	if s.store != nil {
		if bad, why, err := s.store.IsSuppressed(ctx, to); err != nil {
			// Fail OPEN: a lookup error must not stop a permit notification going out.
			log.Printf("notify: suppression lookup for %s: %v", RedactEmail(to), err)
		} else if bad {
			if !(critical && why == store.SuppressUnsubscribed) {
				return fmt.Errorf("%w: %s", ErrSuppressed, why)
			}
			log.Printf("notify: critical notice to unsubscribed %s goes out anyway (unsubscribe mutes routine mail, not safety alerts)", RedactEmail(to))
		}
	}
	c := s.tenantOf(ctx, tenantOwner)
	opts := mailer.Options{UnsubscribeURL: s.UnsubscribeURL(to), Footer: say(c, "mail.footer_affiliation", nil)}
	if reason != "" {
		opts.Provenance = say(c, "mail.provenance", map[string]any{"To": to, "Reason": reason})
	}
	err := s.mail.SendOpts(to, subject, body, opts)
	// Only a REJECTED RECIPIENT earns a suppression. A permanent failure at MAIL
	// FROM or DATA says something is wrong with us or the message, not with this
	// mailbox, and acting on it would blacklist every user we tried to reach.
	if err != nil && errors.Is(err, mailer.ErrBadAddress) && s.store != nil {
		if serr := s.store.SuppressAddress(ctx, to, store.SuppressBounce, err.Error()); serr != nil {
			log.Printf("notify: suppress %s: %v", RedactEmail(to), serr)
		} else {
			// The full address and the server's own diagnostic go in the suppression
			// row, which is where an operator looks and which gets pruned; the log line
			// only needs to say that it happened.
			log.Printf("notify: suppressing %s after the mail server rejected the address", RedactEmail(to))
		}
	}
	return err
}

// NotifyAdmin sends an operator alert to every configured admin channel (email
// AND ntfy), so one channel being down does not blind the operator. Best-effort:
// errors are returned joined but callers typically just log them.
func (s *Service) NotifyAdmin(ctx context.Context, subject, body string) error {
	var errs []string
	if s.adminEmail != "" && s.mail.Enabled() {
		if e := s.mail.Send(s.adminEmail, "[p.stonn admin] "+subject, body); e != nil {
			errs = append(errs, "admin email: "+e.Error())
		}
	}
	if s.adminTopic != "" && s.ntfyBase != "" {
		if e := s.sendNtfy(ctx, s.adminTopic, "[p.stonn admin] "+subject, body, "high", "rotating_light"); e != nil {
			errs = append(errs, "admin ntfy: "+e.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// NotifyRelinkRequired tells the user their tenant connection dropped and they
// must re-link, so an idle session that lapsed does not silently stop managing
// their permit until they get a fine. Always emails the verified address (if
// email is configured), plus push if enabled. Returns the number of channels
// that accepted the message.
func (s *Service) NotifyRelinkRequired(ctx context.Context, owner string) int {
	subject := "Action needed: reconnect your p.stonn council account"
	body := "Your council connection has expired, so p.stonn has stopped updating your visitor permit.\n\n" +
		"Please open the app and re-link your council account so your schedule keeps running. " +
		"Until you do, set your permit's vehicle directly with the council to avoid a fine."
	if s.appURL != "" {
		body += "\n\nRe-link: " + s.appURL
	}
	body += "\nCouncil portal: " + s.tenantOf(ctx, owner).Links.Portal
	return s.broadcastAccount(ctx, owner, "relink", subject, body)
}

// NotifyReconnectStalled tells the household p.stonn cannot sign back in to the
// tenant even though their link is still held (a tenant login outage or a
// changed sign-in page), so their schedule is paused until reconnection
// succeeds. Deliberately NOT a re-link prompt: an interactive re-link goes
// through the same broken login flow, so the honest instruction is to manage
// the permit at the tenant directly until service resumes. Returns the number
// of channels that accepted the message.
func (s *Service) NotifyReconnectStalled(ctx context.Context, owner string) int {
	subject := "p.stonn can't reach the council — your permit schedule is paused"
	body := "p.stonn's sign-in to the council expired, and it has not been able to sign back in for over an hour. " +
		"Until it can, your visitor permit schedule is NOT being applied.\n\n" +
		"That means any change your schedule should make will not happen: if a different car needs to be on the permit, " +
		"change the vehicle yourself on the council website now, or that car is not covered and can be fined.\n\n" +
		"p.stonn keeps retrying automatically and your schedule resumes on its own once the council accepts the sign-in again. " +
		"If this persists, it will email you again if re-linking becomes necessary."
	body += "\n\nCouncil portal: " + s.tenantOf(ctx, owner).Links.Portal
	if s.appURL != "" {
		body += "\nOpen p.stonn: " + s.appURL
	}
	return s.broadcastAccount(ctx, owner, "reconnect-stalled", subject, body)
}

// broadcastAccount delivers an account-critical message to EVERYONE on the
// account (owner + secondaries) — these are the messages where a miss can land
// the whole household a fine, so each member's verified address is emailed
// (channel opt-outs don't apply; suppression in sendEmail still does), plus
// push to each member's topic. tag labels delivery-failure log lines. Returns
// the number of channels that accepted the message.
func (s *Service) broadcastAccount(ctx context.Context, owner, tag, subject, body string) int {
	members, err := s.store.AccountEmails(ctx, owner)
	if err != nil {
		members = []string{owner}
	}
	delivered := 0
	for _, m := range members {
		mpref, _ := s.store.GetNotifyPref(ctx, m)
		if s.mail.Enabled() {
			if e := s.sendEmailCritical(ctx, m, subject, body, reasonAccount); e != nil {
				log.Printf("notify %s email %s: %v", tag, RedactEmail(m), e)
			} else {
				delivered++
			}
		}
		if mpref.NtfyEnabled && s.ntfyBase != "" && mpref.NtfyTopic != "" {
			if e := s.sendNtfy(ctx, mpref.NtfyTopic, subject, body, "high", "warning"); e != nil {
				log.Printf("notify %s ntfy %s: %v", tag, RedactEmail(m), e)
			} else {
				delivered++
			}
		}
	}
	return delivered
}

// NotifyPermitExpiry warns the account that a permit is approaching its expiry
// date, so a lapsed permit doesn't quietly stop being valid. Respects each
// member's channel preferences (routine reminder, not an emergency). Returns the
// number of channels that accepted the message.
func (s *Service) NotifyPermitExpiry(ctx context.Context, owner, permitLabel string, expiry time.Time) int {
	date := expiry.Format("2 Jan 2006")
	subject := fmt.Sprintf("Your %s expires on %s", permitLabel, date)
	body := fmt.Sprintf("Your %s is due to expire on %s.\n\n", permitLabel, date) +
		"p.stonn keeps setting the vehicle, but it can't renew the permit itself — renew it with the council so it stays valid. " +
		"Once you renew, you can copy your schedule onto the new permit in the app."
	if s.appURL != "" {
		body += "\n\nOpen p.stonn: " + s.appURL
	}
	body += "\nRenew with the council: " + s.tenantOf(ctx, owner).Links.Portal
	dels, err := s.accountDeliveries(ctx, owner)
	if err != nil {
		return 0
	}
	delivered := 0
	now := time.Now()
	for _, d := range dels {
		// Safety tier: sent once, weeks ahead, and a lapsed permit fines every
		// visitor — so the verified address is emailed whatever the channel choice
		// (push is added when enabled). Quiet hours are still honoured below.
		wantEmail := s.mail.Enabled()
		wantNtfy := d.pref.NtfyEnabled && s.ntfyBase != "" && d.pref.NtfyTopic != ""
		if !wantEmail && !wantNtfy {
			continue
		}
		// Not an emergency, so it need not wake anyone:
		// honour the member's quiet hours by holding it in the outbox — the
		// expiry-sync runs on the keep-warm cadence at arbitrary times, and a
		// 14-days-ahead warning must not ping anyone at 3am. Queuing counts as
		// reached (the outbox retries it from here).
		if nb := s.quietDefer(d.pref, now); !nb.IsZero() {
			m := outMessage{
				Account: owner, Subject: subject, Body: body,
				NtfyPriority: "default", NtfyTag: "calendar", NotBefore: nb,
				// Keyed on the MEMBER (d.email), not just the account: enqueueSplit
				// suffixes push rows with a bare "|ntfy", so an owner-only key collides
				// across two push-only household members and silently drops the second
				// member's reminder. Every sibling fan-out keys on d.email for this reason.
				DedupKey: fmt.Sprintf("expiry|%s|%s|%s|%s", owner, permitLabel, date, d.email),
				Reason:   reasonAccount,
			}
			if wantEmail {
				m.Recipients = []string{d.email}
			}
			if wantNtfy {
				m.NtfyTopic = d.pref.NtfyTopic
			}
			if s.enqueueSplit(ctx, m) == nil {
				delivered++
			}
			continue
		}
		reached := false
		if wantEmail {
			if e := s.sendEmailCritical(ctx, d.email, subject, body, reasonAccount); e != nil {
				log.Printf("notify permit-expiry email %s: %v", RedactEmail(d.email), e)
			} else {
				reached = true
			}
		}
		if wantNtfy {
			if e := s.sendNtfy(ctx, d.pref.NtfyTopic, subject, body, "default", "calendar"); e != nil {
				log.Printf("notify permit-expiry ntfy %s: %v", RedactEmail(d.email), e)
			} else {
				reached = true
			}
		}
		if reached {
			delivered++
		}
	}
	return delivered
}

// Enabled reports whether any channel is available at all.
func (s *Service) Enabled() bool { return s.mail.Enabled() || s.ntfyBase != "" }

// EmailAvailable / NtfyAvailable report which channels the operator configured
// (so the UI can hide options that can't work).
func (s *Service) EmailAvailable() bool { return s.mail.Enabled() }
func (s *Service) NtfyAvailable() bool  { return s.ntfyBase != "" }

// NtfyBase is the public ntfy server URL, shown in the UI so users can subscribe.
func (s *Service) NtfyBase() string { return s.ntfyBase }

// SendRenewalReminder is the scheduler's re-authorise reminder (email only).
// It builds its own body in the mailer, so the suppression check is inline here
// rather than via sendEmail.
func (s *Service) SendRenewalReminder(ctx context.Context, to string, deadline time.Time, confirmURL string) error {
	if !s.mail.Enabled() {
		return nil
	}
	if s.store != nil {
		if bad, reason, err := s.store.IsSuppressed(ctx, to); err != nil {
			log.Printf("notify: suppression lookup for %s: %v", RedactEmail(to), err)
		} else if bad {
			return fmt.Errorf("%w: %s", ErrSuppressed, reason)
		}
	}
	// Same envelope obligations as every other person-facing mail: an unsubscribe
	// and a "why you got this".
	c := s.tenantOf(ctx, to)
	subject := say(c, "mail.renewal_subject", nil)
	body := say(c, "mail.renewal_body", map[string]any{"When": deadline.Format("Monday 2 January 2006"), "URL": confirmURL})
	err := s.mail.SendOpts(to, subject, body, mailer.Options{
		UnsubscribeURL: s.UnsubscribeURL(to),
		Provenance:     say(c, "mail.provenance", map[string]any{"To": to, "Reason": reasonAccount}),
		Footer:         say(c, "mail.footer_affiliation", nil),
	})
	// As in sendEmail: only a rejected recipient is evidence about this address.
	if err != nil && errors.Is(err, mailer.ErrBadAddress) && s.store != nil {
		if serr := s.store.SuppressAddress(ctx, to, store.SuppressBounce, err.Error()); serr != nil {
			log.Printf("notify: suppress %s: %v", RedactEmail(to), serr)
		}
	}
	return err
}

// ApplyOutcome is what NotifyApply describes to the user: a successful change,
// or a failure with a plain-English reason, the consequence (what plate is still
// on the permit), and what to do. Transient softens the wording (we keep trying).
type ApplyOutcome struct {
	Owner       string
	PermitLabel string
	Reg         string // the vehicle we tried to set
	Name        string // friendly name of that vehicle ("" for an ad-hoc plate)
	By          string // who made the change, when it was a guest activation ("" otherwise)
	Source      string // "roster" / "override" / "guest" / "doorqr" (success context)
	OK          bool
	CurrentReg  string // what is still on the permit on failure ("" if unknown)
	Reason      string // one plain sentence: why it failed
	Action      string // one plain sentence: what the user should do
	Transient   bool   // failure expected to self-heal → soften wording
	// Urgent overrides the transient softening for a CONFIRMED, ongoing block: the
	// change genuinely will not apply until the block clears, so the household must
	// act now (change the plate manually) rather than be reassured it is "still
	// updating". It forces the act-now subject and a high-priority push even though
	// the underlying failure is technically transient.
	Urgent bool

	// DisplacedReg is the plate of a still-live third-party booking this change
	// bumped off the permit ("" when nothing of note was displaced), and
	// DisplacedTold whether its driver got their own heads-up email. When they
	// couldn't be reached, the account notification asks the members to relay
	// the warning — otherwise the displaced car sits uncovered with nobody told.
	DisplacedReg  string
	DisplacedTold bool
}

// actionNeeded reports a hard failure the user must act on (a non-transient
// error: a dead tenant session, a rejected plate). These bypass the quiet-hours
// hold and send immediately — an unattended fine risk shouldn't wait until 6am.
// Urgent counts as action-needed even when Transient. A CONFIRMED fleet block is
// flagged Transient (it will clear) but its body says "change the vehicle yourself at
// the tenant now to avoid a fine" — quiet hours were holding exactly that message
// until 06:00, so a block at 23:30 left the household on the wrong plate all night
// with the high-priority push suppressed.
func (o ApplyOutcome) actionNeeded() bool { return !o.OK && (!o.Transient || o.Urgent) }

// emailWanted decides whether this member's verified address gets the outcome.
// Email-off means "no routine confirmations", never "no safety alerts": an
// action-needed failure ("change the plate yourself now or someone gets a fine")
// always goes to the verified address, the same rule broadcastAccount applies to
// the re-link and reconnect-stalled notices. A push channel has no delivery
// receipt — an uninstalled app, a silenced phone or a wrong topic fails without
// a trace — and this is the one message that must not depend on it. The only
// live push-only household (2026-08) was exactly that exposure.
func (s *Service) emailWanted(pref store.NotifyPref, o ApplyOutcome) bool {
	return (pref.EmailEnabled || o.actionNeeded()) && s.mail.Enabled()
}

// deferUntil returns the quiet-hours delivery time for this outcome, or the zero
// time (send now) when the outcome is a hard action-needed failure.
func (s *Service) deferUntil(pref store.NotifyPref, now time.Time, o ApplyOutcome) time.Time {
	if o.actionNeeded() {
		return time.Time{}
	}
	return s.quietDefer(pref, now)
}

// firstApplyLine is the once-ever referral ask, appended to the confirmation of
// the household's FIRST successful tenant write: the moment the product has just
// proven itself. RecordApply runs before notification, so a count of exactly one
// means this outcome is that first success. Any store error means no line.
func (s *Service) firstApplyLine(ctx context.Context, o ApplyOutcome) string {
	if !o.OK || s.store == nil {
		return ""
	}
	if n, err := s.store.CountSuccessfulApplies(ctx, o.Owner); err != nil || n != 1 {
		return ""
	}
	return "\n\n" + say(s.tenantOf(ctx, o.Owner), "mail.referral_line", nil)
}

// composeApply builds the subject/body/priority/tags for an apply notification,
// shared by the inline NotifyApply (scheduler) and the durable EnqueueApply.
func composeApply(o ApplyOutcome, portalURL string) (subject, body, priority, tags string) {
	// "car" names the vehicle by friendly name and plate where we have both, joined
	// with an em-dash so a nickname that itself contains brackets (e.g.
	// "Anita's Car (Nanny)") doesn't produce confusing nested parentheses.
	car := o.Reg
	if o.Name != "" {
		car = fmt.Sprintf("%s — %s", o.Name, o.Reg)
	}
	if o.OK {
		subject = fmt.Sprintf("Permit updated: %s now shows %s", o.PermitLabel, o.Reg)
		const confirm = "\n\nNothing to do — this is just your confirmation it went through."
		switch {
		case o.Source == "doorqr":
			body = fmt.Sprintf("Your %s is now set to %s.\n\n%s approved a visitor's request from your printed QR code, so it overrides your schedule until that booking ends — then your roster takes over again.",
				o.PermitLabel, car, o.By)
		case o.Source == "guest":
			body = fmt.Sprintf("Your %s is now set to %s.\n\n%s activated it with a guest link, so it overrides your schedule until that booking ends — then your roster takes over again.",
				o.PermitLabel, car, o.By)
		case o.Source == "override" && o.By != "":
			// Name whoever made the booking. On a shared account this is the only
			// signal distinguishing "the schedule ran" from "someone booked over it",
			// and the plate alone doesn't say who decided it.
			body = fmt.Sprintf("Your %s is now set to %s, for a one-off booking made by %s.%s",
				o.PermitLabel, car, o.By, confirm)
		case o.Source == "roster":
			body = fmt.Sprintf("Your %s is now set to %s for today, as scheduled by your weekly roster.%s", o.PermitLabel, car, confirm)
		case o.Source == "override":
			body = fmt.Sprintf("Your %s is now set to %s, for the one-off booking you made.%s", o.PermitLabel, car, confirm)
		default:
			body = fmt.Sprintf("Your %s is now set to %s.%s", o.PermitLabel, car, confirm)
		}
		if o.DisplacedReg != "" {
			if o.DisplacedTold {
				body += fmt.Sprintf("\n\nThis replaced %s, which an active booking had put on — we've emailed the person responsible for that car a heads-up.", o.DisplacedReg)
			} else {
				body += fmt.Sprintf("\n\nThis replaced %s, which an active booking had put on. We had no way to reach whoever drives it — if %s is still parked there, please let them know it's no longer covered.", o.DisplacedReg, o.DisplacedReg)
			}
		}
	} else {
		// A confirmed ongoing block is transient-but-urgent: soften only when it is
		// transient AND not urgent, so the act-now subject and high-priority push
		// fire once we KNOW the change will not apply until the block clears.
		soft := o.Transient && !o.Urgent
		switch {
		case o.CurrentReg != "" && soft:
			subject = fmt.Sprintf("Still updating your %s — it shows %s for now", o.PermitLabel, o.CurrentReg)
		case o.CurrentReg != "":
			subject = fmt.Sprintf("Action needed: your %s still shows %s", o.PermitLabel, o.CurrentReg)
		case soft:
			subject = fmt.Sprintf("Still updating your %s", o.PermitLabel)
		default:
			subject = fmt.Sprintf("Action needed: your %s wasn't updated", o.PermitLabel)
		}
		lines := []string{fmt.Sprintf("p.stonn tried to set your %s to %s but couldn't.", o.PermitLabel, car)}
		if o.CurrentReg != "" {
			lines = append(lines, fmt.Sprintf("The permit still shows %s, so that is the vehicle currently covered.", o.CurrentReg))
		} else {
			lines = append(lines, "The vehicle on the permit has not been changed.")
		}
		if o.Reason != "" {
			lines = append(lines, "", o.Reason)
		}
		if o.Action != "" {
			lines = append(lines, o.Action)
		}
		// A failure is a "sort it yourself" moment: link the tenant portal.
		lines = append(lines, "", "You can set the vehicle on your permit yourself at the council:", portalURL)
		body = strings.Join(lines, "\n")
	}
	priority, tags = "default", "white_check_mark"
	if !o.OK {
		tags = "warning"
		if o.Transient && !o.Urgent {
			priority = "default"
		} else {
			priority = "high"
		}
	}
	return
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

// EnqueueApply durably queues an apply notification, for paths with no reconcile-
// loop retry behind them (a guest activation): a failed send is retried by the
// outbox instead of dropped. Enqueues ONE message per account member, each
// honouring that member's own channels + failures-only, and dedups per member so
// a repeated activation of the same plate doesn't double-notify anyone.
func (s *Service) EnqueueApply(ctx context.Context, o ApplyOutcome) error {
	dels, err := s.accountDeliveries(ctx, o.Owner)
	if err != nil {
		return err
	}
	subject, body, priority, tags := composeApply(o, s.tenantOf(ctx, o.Owner).Links.Portal)
	if s.appURL != "" {
		body += "\n\n" + s.appURL
	}
	body += s.firstApplyLine(ctx, o)
	now := time.Now()
	for _, d := range dels {
		if o.OK && d.pref.FailuresOnly {
			continue
		}
		m := outMessage{
			Account: o.Owner,
			Subject: subject, Body: body, NtfyPriority: priority, NtfyTag: tags,
			DedupKey:  fmt.Sprintf("apply|%s|%s|%s|%s|%t", d.email, o.Owner, o.PermitLabel, o.Reg, o.OK),
			NotBefore: s.deferUntil(d.pref, now, o),
			Reason:    reasonAccount,
		}
		if s.emailWanted(d.pref, o) {
			m.Recipients = []string{d.email}
		}
		if d.pref.NtfyEnabled && s.ntfyBase != "" && d.pref.NtfyTopic != "" {
			m.NtfyTopic = d.pref.NtfyTopic
		}
		if len(m.Recipients) == 0 && m.NtfyTopic == "" {
			continue // this member has no reachable channel
		}
		if err := s.enqueueSplit(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

// NotifyApply tells everyone on the account about an apply outcome, each by the
// channels THEY chose (a secondary's email-off doesn't silence the primary). It
// returns how many members were reached: the caller uses 0 to mean "nobody was
// reached" so it can escalate to the operator and retry, rather than silently
// marking the outcome as delivered. -1 means intentionally not sent (nobody was
// due a notification — all suppressed by failures-only, or no channels enabled).
func (s *Service) NotifyApply(ctx context.Context, o ApplyOutcome) (delivered int, err error) {
	dels, err := s.accountDeliveries(ctx, o.Owner)
	if err != nil {
		return 0, err
	}
	subject, body, priority, tags := composeApply(o, s.tenantOf(ctx, o.Owner).Links.Portal)
	emailBody := body
	if s.appURL != "" {
		emailBody += "\n\n" + s.appURL
	}
	emailBody += s.firstApplyLine(ctx, o)
	var errs []string
	due := 0 // members with at least one channel that should have received this
	now := time.Now()
	for _, d := range dels {
		if o.OK && d.pref.FailuresOnly {
			continue
		}
		wantEmail := s.emailWanted(d.pref, o)
		wantNtfy := d.pref.NtfyEnabled && s.ntfyBase != "" && d.pref.NtfyTopic != ""
		if !wantEmail && !wantNtfy {
			continue // no reachable channel for this member
		}
		due++

		// Quiet hours: hold this member's notice and deliver it via the durable
		// outbox at the window's end, so a midnight roster change lands as a 6am
		// confirmation rather than a 12:01am ping. Queuing counts as reached.
		if nb := s.deferUntil(d.pref, now, o); !nb.IsZero() {
			m := outMessage{
				Account: o.Owner, Subject: subject, Body: emailBody,
				NtfyPriority: priority, NtfyTag: tags, NotBefore: nb,
				DedupKey: fmt.Sprintf("apply|%s|%s|%s|%s|%t", d.email, o.Owner, o.PermitLabel, o.Reg, o.OK),
				Reason:   reasonAccount,
			}
			if wantEmail {
				m.Recipients = []string{d.email}
			}
			if wantNtfy {
				m.NtfyTopic = d.pref.NtfyTopic
			}
			if e := s.enqueueSplit(ctx, m); e != nil {
				errs = append(errs, "queue "+d.email+": "+e.Error())
			} else {
				delivered++
			}
			continue
		}

		reached := false
		if wantEmail {
			// An action-needed failure ("change the plate yourself now or someone
			// gets a fine") rides the critical path: a self-service unsubscribe
			// mutes routine confirmations, not this.
			send := s.sendEmail
			if o.actionNeeded() {
				send = s.sendEmailCritical
			}
			if e := send(ctx, d.email, subject, emailBody, reasonAccount); e != nil {
				errs = append(errs, "email "+d.email+": "+e.Error())
			} else {
				reached = true
			}
		}
		if wantNtfy {
			if e := s.sendNtfy(ctx, d.pref.NtfyTopic, subject, body, priority, tags); e != nil {
				errs = append(errs, "ntfy "+d.email+": "+e.Error())
			} else {
				reached = true
			}
		}
		if reached {
			delivered++
		}
	}
	if due == 0 {
		return -1, nil // nobody was due a notification
	}
	if len(errs) > 0 {
		return delivered, fmt.Errorf("notify %s: %s", o.Owner, strings.Join(errs, "; "))
	}
	return delivered, nil
}

// SendTest sends a "notifications are working" message on the acting user's OWN
// enabled channels (their email, their push topic), so each person confirms their
// own setup — a secondary's test doesn't reach the primary and vice versa.
func (s *Service) SendTest(ctx context.Context, user string) error {
	pref, err := s.store.GetNotifyPref(ctx, user)
	if err != nil {
		return err
	}
	const subject = "p.stonn test notification"
	const body = "This is a test. Your permit-change notifications are set up correctly."
	var errs []string
	if pref.EmailEnabled && s.mail.Enabled() {
		if e := s.sendEmail(ctx, user, subject, body, reasonTest); e != nil {
			errs = append(errs, "email "+user+": "+e.Error())
		}
	}
	if pref.NtfyEnabled && s.ntfyBase != "" && pref.NtfyTopic != "" {
		if e := s.sendNtfy(ctx, pref.NtfyTopic, subject, body, "default", "bell"); e != nil {
			errs = append(errs, "ntfy: "+e.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// NotifyDisconnected tells the user their tenant account was disconnected,
// e.g. after they declined updated terms. Because it's important, it always
// emails their verified address (if email is configured), plus push if enabled.
func (s *Service) NotifyDisconnected(ctx context.Context, owner string) error {
	pref, err := s.store.GetNotifyPref(ctx, owner)
	if err != nil {
		return err
	}
	const subject = "Your p.stonn account has been disconnected"
	const body = "You declined p.stonn's updated terms, so your council account has been disconnected and your permit is no longer being managed.\n\nPlease check your visitor permit with the council. To reconnect, sign in again and accept the terms."
	var errs []string
	if s.mail.Enabled() {
		// "Your permit is no longer being managed" is a safety notice, not a
		// courtesy: an unsubscribe must not swallow it.
		if e := s.sendEmailCritical(ctx, owner, subject, body, reasonAccount); e != nil {
			errs = append(errs, "email: "+e.Error())
		}
	}
	if pref.NtfyEnabled && s.ntfyBase != "" && pref.NtfyTopic != "" {
		if e := s.sendNtfy(ctx, pref.NtfyTopic, subject, body, "high", "warning"); e != nil {
			errs = append(errs, "ntfy: "+e.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// SendInvite emails a courtesy heads-up to someone who has just been granted
// shared access, so they know to sign in. It is NOT an access grant or a code:
// access still only takes effect when they sign in with this email and get the
// normal one-time login code. Email only (they may have no push set up yet), and
// a no-op when SMTP is unconfigured.
func (s *Service) SendInvite(ctx context.Context, to, ownerEmail string) error {
	if !s.mail.Enabled() {
		return nil
	}
	subject := "You have been given access to a p.stonn account"
	lines := []string{
		say(s.tenantOf(ctx, ownerEmail), "mail.invite_lead", map[string]any{"Owner": ownerEmail}),
		"",
		"Sign in with this email address — you will get a one-time code to confirm it is you — then tap Accept on the page you land on.",
		"",
		"Already using p.stonn with your own permits? The invitation is under Settings. You can't join another account while you keep your own.",
	}
	if s.appURL != "" {
		lines = append(lines, "", s.appURL)
	}
	lines = append(lines,
		"",
		"If you were not expecting this, you can ignore this email. You can also remove your access from Settings after signing in.")
	return s.sendEmail(ctx, to, subject, strings.Join(lines, "\n"), reasonInvite)
}

// SendOnboardNudge emails a stalled signup — someone who accepted the terms but
// never connected a tenant account — the once-ever recovery note. Email is the
// only channel that can reach them: they never got far enough to configure
// anything else, and (observed live, 2026-08) most arrived inside the Facebook
// in-app browser, where closing the webview severs every other path back.
//
// The body walks the three things the access logs showed actually stop people:
// not having the ePermits password to hand (with the tenant's reset deep link,
// which also serves the resident whose account predates the portal and has
// never had a working password), a p.stonn email that doesn't match the
// ePermits one, and the in-app browser holding their password manager hostage.
//
// The caller decides what "sent" means for its once-ever bookkeeping; this
// method just reports the send outcome (including ErrSuppressed).
func (s *Service) SendOnboardNudge(ctx context.Context, to string) error {
	if !s.mail.Enabled() {
		return nil
	}
	subject, body := onboardNudgeMessage(to, s.appURL, s.tenantOf(ctx, to))
	return s.sendEmail(ctx, to, subject, body, reasonOnboard)
}

// onboardNudgeMessage composes the recovery email. Split from the send so its
// content — each line answers a distinct observed drop-off cause — is testable
// without an SMTP conversation.
func onboardNudgeMessage(to, appURL string, c mailTenant) (subject, body string) {
	subject = "One step left to start managing your visitor permit"
	// Layout note: a SHORT "do this:" line directly above each URL becomes that
	// button's label in the HTML alternative (see mailer/html.go). Folding the
	// label into the preceding sentence puts the whole sentence on the button.
	lines := []string{
		"You signed up for p.stonn, but it isn't connected to your council account yet — so nothing is running. The weekly plate schedule, guest QR codes and one-off bookings all start from that one connection.",
		"",
		say(c, "mail.nudge_connect", nil),
		"",
		say(c, "mail.nudge_password", nil),
		"Reset it at the council:",
		c.Links.ResetPassword,
		"",
		say(c, "mail.nudge_email", map[string]any{"To": to}),
		"",
	}
	// The webview escape needs somewhere to point; a deployment that never set
	// its public URL keeps the advice without the address.
	if appURL != "" {
		lines = append(lines,
			"3. Your usual browser. If you signed up from a Facebook link, you were inside Facebook's built-in browser, where saved passwords don't auto-fill.",
			"Open p.stonn in Safari or Chrome:",
			appURL,
			"")
	} else {
		lines = append(lines,
			"3. Your usual browser. If you signed up from a Facebook link, you were inside Facebook's built-in browser, where saved passwords don't auto-fill. Open p.stonn in Safari or Chrome instead.",
			"")
	}
	lines = append(lines,
		"One thing to know: p.stonn manages VISITOR permits only — the permit your guests' cars go on — and only one you already hold; it can't apply for one, and it never touches a resident permit.",
		"",
		say(c, "mail.nudge_apply", nil),
		"Register with the council:",
		c.Links.Register,
		"",
		"This is the only reminder p.stonn sends. If you've decided it's not for you, there's nothing to undo — your details go no further than the sign-up you made.",
	)
	return subject, strings.Join(lines, "\n")
}

// SendGuestLink emails a recipient their personal guest-pass link (email only,
// no-op without SMTP). The link lets them set one of the account's cars on the
// visitor permit without an account of their own.
func (s *Service) SendGuestLink(ctx context.Context, to, ownerEmail, permitLabel, url string) error {
	if !s.mail.Enabled() {
		return nil
	}
	subject := "Your link to set a car on " + ownerEmail + "'s parking permit"
	lines := []string{
		// The label is free text the owner typed, and this recipient is whoever the
		// owner named — so it goes in stripped of anything the mail layer would turn
		// into a clickable link. It stays in the body because it is how the recipient
		// knows WHICH permit this is ("Nanny", the flat number), which matters in a
		// household with more than one.
		say(s.tenantOf(ctx, ownerEmail), "mail.guest_lead", map[string]any{"Owner": ownerEmail, "Label": neutraliseLinks(permitLabel)}),
		"",
		"When you arrive, open the link and choose your car. It stays on the permit until the end of the day.",
		"",
		url,
		"",
		"Tip: bookmark this link or add it to your phone's home screen — then next time you can open it in one tap, without hunting for this email. The same link works every time.",
		"",
		"Keep this link to yourself. If you were not expecting it, you can ignore this email.",
		"",
		say(s.tenantOf(ctx, ownerEmail), "mail.guest_promo", nil),
	}
	return s.sendEmailAs(ctx, ownerEmail, to, subject, strings.Join(lines, "\n"), reasonGuest, false)
}

// NotifyDriverDisplaced warns whoever is responsible for a displaced car (the
// guest who booked it, or the saved vehicle's attached driver — someone with no
// account, so email only) that the car is no longer on the permit, so they can
// move it or get it put back before getting caught out. No-op without SMTP.
func (s *Service) NotifyDriverDisplaced(ctx context.Context, owner, to, permitLabel, oldReg, how string, at time.Time) error {
	if !s.mail.Enabled() {
		return nil
	}
	// What happened, when, whose permit, what to do — never the replacing plate:
	// that is another visitor's registration, and it gives this driver nothing to
	// act on.
	subject := fmt.Sprintf("Heads up: %s is no longer covered on the visitor permit", oldReg)
	when := at.In(s.loc).Format("3:04pm")
	lines := []string{
		fmt.Sprintf("Your car %s came off the visitor parking permit for %s at %s — %s.", oldReg, permitLabel, when, how),
		"",
		"If your car is still parked there it's no longer covered. Move it, or put it back on with your link, or check with the permit holder.",
	}
	if !s.displacedTo.allow(to) {
		log.Printf("notify: displaced-driver notice to %s throttled (per-recipient cap)", RedactEmail(to))
		return nil
	}
	key := fmt.Sprintf("displaced|%s|%s|%s", to, permitLabel, oldReg)
	return s.enqueue(ctx, outMessage{Account: owner, Recipients: []string{to}, Subject: subject,
		Body: strings.Join(lines, "\n"), DedupKey: key, Reason: reasonDisplace})
}

// NotifyGuestRequest tells the account (all members) that someone scanned a
// printed QR and is asking to put a plate on the permit, so they can approve or
// decline it in the app. Each member is nudged on the channels THEY chose (the
// EnqueueApply pattern) — a push-only secondary gets the push on their own
// topic, not silence. Two deliberate departures from the apply pattern:
// failures-only does not apply (this is a question, not an outcome), and quiet
// hours are NOT honoured — the visitor is standing at the door now, and the
// request expires unanswered within the hour.
func (s *Service) NotifyGuestRequest(ctx context.Context, owner, permitLabel, plate, url string, reqID int64) error {
	subject := fmt.Sprintf("Approve %s on your %s?", plate, permitLabel)
	lines := []string{
		fmt.Sprintf("Someone scanned your printed QR code and is asking to put %s on your %s.", plate, permitLabel),
		"",
		"Open p.stonn to allow it (until the end of the day) or decline. Nothing is on the permit until you approve.",
	}
	if url != "" {
		lines = append(lines, "", url)
	}
	body := strings.Join(lines, "\n")
	dels, err := s.accountDeliveries(ctx, owner)
	if err != nil {
		return err
	}
	var errs []string
	for _, d := range dels {
		m := outMessage{
			Account: owner, Subject: subject, Body: body,
			NtfyPriority: "high", NtfyTag: "bell",
			Reason: reasonAccount,
			// Per-member key (then per-target suffix in enqueueSplit): a re-scan of
			// the same plate while the first nudge is still fresh doesn't re-notify
			// anyone, and one member's rows never dedup away another member's.
			DedupKey: fmt.Sprintf("guestreq|%s|%s|%s|%s", d.email, owner, permitLabel, plate),
		}
		// The email additionally carries this member's signed one-tap decide link.
		// EMAIL ONLY, never the push: an ntfy topic is readable by anyone who
		// learns its name, and a topic that leaked must stay read-only — it must
		// not start carrying the capability to put a plate on the permit. So the
		// member's email and ntfy nudges are enqueued as SEPARATE messages with
		// different bodies (same dedup key; enqueueSplit's per-target suffix
		// already keeps the rows distinct).
		if d.pref.EmailEnabled && s.mail.Enabled() {
			em := m
			em.Recipients = []string{d.email}
			if link := s.GuestDecideURL(reqID, d.email); link != "" {
				em.Body = body + "\n\nOr approve or decline in one tap, no sign-in needed:\n" + link +
					"\n(This link can only answer this one request, and only from your address.)"
			}
			if e := s.enqueueSplit(ctx, em); e != nil {
				errs = append(errs, d.email+": "+e.Error())
			}
		}
		if d.pref.NtfyEnabled && s.ntfyBase != "" && d.pref.NtfyTopic != "" {
			pm := m
			pm.NtfyTopic = d.pref.NtfyTopic
			if e := s.enqueueSplit(ctx, pm); e != nil {
				errs = append(errs, d.email+": "+e.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("guest request notify: %s", strings.Join(errs, "; "))
	}
	return nil
}

// NotifyAccountChange tells an account's members that someone made an
// irreversible change to the setup — a wiped roster, a deleted car, a retired
// permit, a revoked pass. The person who made the change is skipped: they know.
//
// It exists because the notification design otherwise only fires on tenant
// apply outcomes, so configuration changes were invisible by construction: an
// emptied roster produces no apply at all, and the household would discover it
// from a parking ranger. Quiet hours ARE honoured (this is information, not an
// emergency) and failures-only is ignored, since an unexpected deletion is
// exactly the kind of thing a failures-only subscriber still wants.
func (s *Service) NotifyAccountChange(ctx context.Context, owner, actor, summary string) error {
	subject := "A change was made to your p.stonn setup"
	lines := []string{
		summary,
		"",
		"If that was expected, nothing to do.",
		"If it wasn't, open p.stonn — the Activity page lists every change and who made it, and you can review who has shared access in Settings.",
	}
	if s.appURL != "" {
		lines = append(lines, "", s.appURL+"/activity")
	}
	body := strings.Join(lines, "\n")
	dels, err := s.accountDeliveries(ctx, owner)
	if err != nil {
		return err
	}
	now := time.Now()
	var errs []string
	for _, d := range dels {
		if strings.EqualFold(d.email, actor) {
			continue // don't tell someone about their own action
		}
		m := outMessage{
			Account: owner, Subject: subject, Body: body, Reason: reasonAccount,
			NotBefore: s.quietDefer(d.pref, now),
			// Per-member and per-summary, so two members each hear once and a repeated
			// identical action inside the dedup window doesn't double up.
			DedupKey: fmt.Sprintf("acctchange|%s|%s|%s", d.email, owner, summary),
		}
		if d.pref.EmailEnabled && s.mail.Enabled() {
			m.Recipients = []string{d.email}
		}
		if d.pref.NtfyEnabled && s.ntfyBase != "" && d.pref.NtfyTopic != "" {
			m.NtfyTopic = d.pref.NtfyTopic
		}
		if len(m.Recipients) == 0 && m.NtfyTopic == "" {
			continue
		}
		if e := s.enqueueSplit(ctx, m); e != nil {
			errs = append(errs, d.email+": "+e.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("account change notify: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (s *Service) sendNtfy(ctx context.Context, topic, title, body, priority, tags string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.ntfyBase+"/"+topic, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", priority)
	req.Header.Set("Tags", tags)
	if s.ntfyToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.ntfyToken)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Drain so the keep-alive connection is reusable.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy returned status %d", resp.StatusCode)
	}
	return nil
}

// RandomTopic returns an unguessable ntfy topic for a new user (topics are the
// only access control on a public ntfy server, so they must not be guessable).
// RandomTopic returns an unguessable but easy-to-type ntfy topic. An ntfy topic
// is a shared secret the user types by hand into the phone app, so we favour a
// pronounceable, unambiguous form (alternating consonant/vowel syllables in
// hyphen-separated groups, no look-alike letters like l/1/o/0) over raw hex.
// Four four-letter groups give roughly 52 bits of entropy: ample for what is a
// low-stakes, rate-limited read capability, while staying quick to key in.
func RandomTopic() string {
	const cons = "bcdfghjkmnpqrstvwxz" // consonants, minus ambiguous l and y
	const vows = "aeiou"
	b := make([]byte, 16)
	_, _ = crand.Read(b)
	var sb strings.Builder
	sb.WriteString("pstonn")
	for i := 0; i < len(b); i++ {
		if i%4 == 0 {
			sb.WriteByte('-')
		}
		if i%2 == 0 {
			sb.WriteByte(cons[int(b[i])%len(cons)])
		} else {
			sb.WriteByte(vows[int(b[i])%len(vows)])
		}
	}
	return sb.String()
}

// ---- durable notification outbox ----
//
// Enqueue composes and addresses a message, then a single worker (RunOutbox)
// delivers it with retry/backoff, so a send survives a restart and a failed
// attempt is retried instead of silently dropped.

const (
	outboxMaxAttempts = 8
	outboxTick        = 15 * time.Second
	outboxBatch       = 50
)

// outMessage is a composed, addressed notification ready to enqueue.
type outMessage struct {
	Account      string // owner the message concerns (so account deletion purges it)
	DedupKey     string
	Recipients   []string
	NtfyTopic    string
	NtfyPriority string
	NtfyTag      string
	Subject      string
	Body         string
	NotBefore    time.Time // earliest delivery (quiet-hours defer); zero = immediate
	Reason       string    // "why you got this", for the mail footer
}

func (s *Service) enqueue(ctx context.Context, m outMessage) error {
	return s.store.EnqueueOutbox(ctx, store.OutboxItem{
		Account: m.Account, DedupKey: m.DedupKey, Reason: m.Reason, Recipients: m.Recipients, NtfyTopic: m.NtfyTopic,
		NtfyPriority: m.NtfyPriority, NtfyTag: m.NtfyTag, Subject: m.Subject, Body: m.Body,
		NotBefore: m.NotBefore,
	})
}

// enqueueSplit stores one outbox row per recipient per channel. A combined row
// has two failure modes the outbox cannot express: deliver() treats one accepted
// email as row success (silently dropping the other recipients forever), and a
// retry of a failed channel re-sends the channel that already succeeded
// (duplicate ntfy pushes on every attempt). One target per row makes success,
// retry, and dead-lettering exact. Dedup keys are suffixed per target so
// deduplication stays per-recipient.
func (s *Service) enqueueSplit(ctx context.Context, m outMessage) error {
	var errs []string
	for _, r := range m.Recipients {
		row := m
		row.Recipients = []string{r}
		row.NtfyTopic = ""
		if row.DedupKey != "" {
			row.DedupKey += "|email|" + r
		}
		if err := s.enqueue(ctx, row); err != nil {
			errs = append(errs, "queue email "+r+": "+err.Error())
		}
	}
	if m.NtfyTopic != "" {
		row := m
		row.Recipients = nil
		if row.DedupKey != "" {
			row.DedupKey += "|ntfy"
		}
		if err := s.enqueue(ctx, row); err != nil {
			errs = append(errs, "queue ntfy: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// RunOutbox drains the outbox until ctx is cancelled, retrying failed sends with
// backoff and dead-lettering (with an operator alert) after too many tries. It
// also periodically purges delivered rows. Start it once from main.
func (s *Service) RunOutbox(ctx context.Context) {
	t := time.NewTicker(outboxTick)
	defer t.Stop()
	purge := time.NewTicker(6 * time.Hour)
	defer purge.Stop()
	s.drainOutbox(ctx) // flush promptly on startup (a restart resumes pending sends)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.drainOutbox(ctx)
		case <-purge.C:
			// 24h, not 7 days: a sent row is stripped of its content at send and is
			// only needed for the 15-minute dedup window, so a day is generous.
			if _, err := s.store.PurgeSentOutbox(ctx, time.Now().Add(-24*time.Hour)); err != nil {
				log.Printf("notify: purge outbox: %v", err)
			}
		}
	}
}

// outboxUpdate is the bookkeeping the drain owes the store for a row it has
// already acted on: delivered, retired, or waiting on a backoff. It is carried as
// data rather than written inline so a write the store REFUSES can be retried on
// a later pass instead of being lost — see the unrecorded map.
//
// It deliberately holds no message content: `who` is already redacted, so parking
// a row does not keep a copy of the recipient or subject in memory.
type outboxUpdate struct {
	status   string // "sent", "dead", or "retry"
	attempts int
	next     time.Time
	lastErr  string
	who      string // redacted recipient/topic, for the dead-letter announcement
	why      string // why it was retired, for the same
}

// maxUnrecorded bounds the parked set. In practice it never exceeds one: the
// first refused write stops the rest of the pass, so nothing new is sent (and
// therefore nothing new is parked) until that one write succeeds. The cap is
// there so a pathological intermittent failure cannot grow the map without
// bound.
const maxUnrecorded = 256

func (s *Service) drainOutbox(ctx context.Context) {
	if s.unrecorded == nil {
		s.unrecorded = map[int64]outboxUpdate{}
	}
	// Settle what we already owe BEFORE sending anything new. These rows have been
	// delivered (or retired) and are still 'pending' with next_attempt in the past
	// only because the store refused the write, so DueOutbox would hand them back
	// and we would send the very same email again.
	if !s.flushUnrecorded(ctx) {
		// Still refusing writes. Send nothing at all this pass: a delayed
		// notification is recoverable, but a send loop against a live mailbox —
		// 50 rows every 15 seconds for as long as the disk stays full — is the
		// reputation event the whole suppression list exists to prevent.
		return
	}
	due, err := s.store.DueOutbox(ctx, time.Now(), outboxBatch)
	if err != nil {
		log.Printf("notify: read outbox: %v", err)
		return
	}
	for _, it := range due {
		if ctx.Err() != nil {
			return
		}
		if _, parked := s.unrecorded[it.ID]; parked {
			continue // already delivered; we just cannot say so yet
		}
		lastErr, permanent := s.deliver(ctx, it)
		upd := outboxUpdate{status: "sent", who: outboxTarget(it)}
		switch attempts := it.Attempts + 1; {
		case lastErr == "":
		case permanent || attempts >= outboxMaxAttempts:
			upd.status, upd.attempts, upd.lastErr = "dead", attempts, lastErr
			upd.why = fmt.Sprintf("after %d attempts", attempts)
			if permanent {
				upd.why = "permanently refused"
			}
		default:
			upd.status, upd.attempts, upd.lastErr = "retry", attempts, lastErr
			upd.next = time.Now().Add(outboxBackoff(attempts))
		}
		if !s.record(ctx, it.ID, upd) {
			return // the store is not accepting writes; stop sending (see flushUnrecorded)
		}
	}
}

// outboxTarget names a row's destination in redacted form, for logs and operator
// alerts. An ntfy topic is a shared secret (it is the only access control on the
// push server), so it is never written out either.
func outboxTarget(it store.OutboxItem) string {
	if len(it.Recipients) > 0 {
		return redactEmails(it.Recipients)
	}
	if it.NtfyTopic != "" {
		return "a push topic"
	}
	return "(none)"
}

// record applies one row's bookkeeping. On success the row leaves the parked set;
// on failure it enters it, and the caller must stop draining. Reports whether the
// store accepted the write.
func (s *Service) record(ctx context.Context, id int64, u outboxUpdate) bool {
	// DETACHED. mailer.Send* takes no context, so a send is uncancellable — but this
	// bookkeeping was threaded the signal context. On SIGTERM mid-send the mail goes
	// out, this write fails instantly with context.Canceled, the row stays 'pending'
	// with next_attempt in the past, and the startup drain re-sends it. The whole
	// unrecorded/flushUnrecorded machinery exists to prevent exactly that duplicate and
	// was defeated by the one failure mode guaranteed to end the process.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var err error
	switch u.status {
	case "sent":
		err = s.store.MarkOutboxSent(ctx, id)
	case "dead":
		err = s.store.MarkOutboxDead(ctx, id, u.lastErr)
	default:
		err = s.store.RescheduleOutbox(ctx, id, u.attempts, u.next, u.lastErr)
	}
	if err != nil {
		s.park(ctx, id, u, err)
		return false
	}
	delete(s.unrecorded, id)
	if u.status == "dead" {
		s.announceDead(ctx, id, u)
	}
	return true
}

// park remembers bookkeeping the store refused, so a later pass can complete it
// instead of re-delivering the row. This is the failure the drain used to discard
// silently: a read-only remount or a full disk left the row 'pending' with
// next_attempt in the past, and the same email went out every 15 seconds with
// nothing anywhere saying so.
func (s *Service) park(ctx context.Context, id int64, u outboxUpdate, err error) {
	log.Printf("notify: outbox row %d was %s but the store refused the bookkeeping write (%v) — "+
		"parking it and sending nothing further until that write lands", id, u.status, err)
	if len(s.unrecorded) < maxUnrecorded {
		s.unrecorded[id] = u
	}
	// Escalate too: an unwritable store does not fix itself (a full disk, a
	// read-only remount), and every notification is now stalled behind it. Hourly,
	// because the drain retries every 15 seconds and NotifyAdmin sends real mail.
	if now := time.Now(); now.Sub(s.lastWriteAlert) > time.Hour {
		s.lastWriteAlert = now
		if ae := s.NotifyAdmin(ctx, "Notification outbox cannot be written",
			fmt.Sprintf("A notification was delivered but the database would not record it (%v).\n"+
				"Outbox row: %d\n\nNotifications are PAUSED until the write succeeds, so that the "+
				"delivered message is not sent again on every retry. Check disk space and that the "+
				"database volume is writable.", err, id)); ae != nil {
			log.Printf("notify: outbox-write admin alert also failed: %v", ae)
		}
	}
}

// flushUnrecorded retries the bookkeeping owed for rows already acted on.
// Reports whether the store is accepting writes (true when there was nothing to
// do).
func (s *Service) flushUnrecorded(ctx context.Context) bool {
	for id, u := range s.unrecorded {
		if ctx.Err() != nil {
			return false
		}
		if !s.record(ctx, id, u) {
			return false
		}
		log.Printf("notify: outbox row %d bookkeeping recorded on retry (%s)", id, u.status)
	}
	return true
}

// announceDead surfaces a dropped notification. The DB 'dead' row is otherwise
// unsurfaced, and the escalation itself may share the very channel that failed,
// so a failure to escalate is logged as well.
//
// The row id, not the message: the subject carries the permit label (typically a
// street address) and a plate, and the row itself is still in the DB for a day if
// an operator needs the detail.
func (s *Service) announceDead(ctx context.Context, id int64, u outboxUpdate) {
	log.Printf("notify: DROPPED outbox row %d (%s) to %s: %s", id, u.why, u.who, u.lastErr)
	if ae := s.NotifyAdmin(ctx, "Notification undeliverable (gave up)",
		fmt.Sprintf("A notification could not be delivered (%s) and was dropped.\nOutbox row: %d\nTo: %s\nLast error: %s",
			u.why, id, u.who, u.lastErr)); ae != nil {
		log.Printf("notify: dead-letter admin alert also failed: %v", ae)
	}
}

// deliver attempts every channel and returns "" if at least one accepted (or there
// was nothing addressable), else a joined error so the item is retried. permanent
// reports that every failure was a hard refusal (a 5xx), so retrying is futile
// and the caller should dead-letter immediately instead of burning eight attempts
// against an address the server has already rejected.
func (s *Service) deliver(ctx context.Context, it store.OutboxItem) (lastErr string, permanent bool) {
	var errs []string
	allPermanent := true
	// Email is the reliable channel. When the message HAS email recipients, success
	// requires at least one email to be accepted — an ntfy 200 (which the server
	// returns even with no subscriber) must not mask a total email failure and
	// silently drop the account's email. When there is no email, ntfy gates.
	emailTargets, emailOK := 0, false
	if s.mail.Enabled() {
		for _, addr := range it.Recipients {
			// A suppressed address is not a target at all: it must not count toward
			// emailTargets, or a row addressed ONLY to a dead address would retry
			// eight times and then dead-letter, which is exactly the reputation
			// damage the suppression list exists to prevent.
			e := s.sendEmail(ctx, addr, it.Subject, it.Body, it.Reason)
			if errors.Is(e, ErrSuppressed) {
				log.Printf("notify: skipping suppressed recipient %s (outbox row %d)", RedactEmail(addr), it.ID)
				continue
			}
			emailTargets++
			if e != nil {
				// Redacted: this string is stored in last_error and repeated in the
				// dead-letter log and operator alert, so the full address would end up in
				// three places that all outlive the notification.
				errs = append(errs, "email "+RedactEmail(addr)+": "+e.Error())
				if !errors.Is(e, mailer.ErrPermanent) {
					allPermanent = false
				}
			} else {
				emailOK = true
			}
		}
	}
	// A row addressing BOTH channels cannot express partial success: the outbox
	// keeps one status per row, so an email failure sends the whole row round the
	// retry loop and re-pushes an ntfy message that already worked — up to eight
	// duplicate pushes for one event. enqueueSplit gives every target its own row
	// precisely so this shape never exists, but the invariant belongs HERE, in the
	// only code that would do the duplicating: push at most once, on the first
	// attempt, and let email decide the row's fate as usual.
	mixed := len(it.Recipients) > 0 && it.NtfyTopic != ""
	if mixed && it.Attempts == 0 {
		log.Printf("notify: outbox row %d addresses email and push in one row; "+
			"pushing once only, since a retry cannot un-push it (enqueueSplit should have split it)", it.ID)
	}
	ntfyTargets, ntfyOK := 0, false
	if it.NtfyTopic != "" && s.ntfyBase != "" && !(mixed && it.Attempts > 0) {
		ntfyTargets++
		pr := it.NtfyPriority
		if pr == "" {
			pr = "default"
		}
		if e := s.sendNtfy(ctx, it.NtfyTopic, it.Subject, it.Body, pr, it.NtfyTag); e != nil {
			errs = append(errs, "ntfy: "+e.Error())
			allPermanent = false // an ntfy failure is always worth retrying
		} else {
			ntfyOK = true
		}
	}
	switch {
	case emailTargets > 0:
		if emailOK {
			return "", false // reached via the reliable channel (ntfy is a bonus on top)
		}
	case ntfyTargets > 0:
		if ntfyOK {
			return "", false // no email configured; ntfy was all we had and it worked
		}
	default:
		// Nothing addressable: every channel is off, or every recipient is
		// suppressed. Nothing to retry.
		return "", false
	}
	return strings.Join(errs, "; "), allPermanent && len(errs) > 0
}

// outboxBackoff spaces retries: ~1m, 3m, 9m, 27m, ... capped at 3h.
func outboxBackoff(attempts int) time.Duration {
	d := time.Minute
	for i := 1; i < attempts; i++ {
		d *= 3
		if d > 3*time.Hour {
			return 3 * time.Hour
		}
	}
	return d
}

// SendFortnightNudge is the once-ever "tell a neighbour" note, sent a fortnight
// after the household's first successful tenant write (see the scheduler sweep).
func (s *Service) SendFortnightNudge(ctx context.Context, to string) error {
	if !s.mail.Enabled() {
		return nil
	}
	base := strings.TrimRight(s.appURL, "/")
	if base == "" {
		base = "https://p.stonn.org"
	}
	subject := "p.stonn — a quick one"
	body := strings.Join([]string{
		"Hi — you've had p.stonn looking after your visitor permit for a couple of weeks now.",
		"",
		say(s.tenantOf(ctx, to), "mail.fortnight_line", nil),
		"",
		"Send them an invite: " + base + "/share",
		"Or print a card with a QR code they can scan to get started: " + base + "/share#card",
	}, "\n")
	return s.sendEmail(ctx, to, subject, body, reasonAccount)
}

// SendReferralInvite is the introduction a signed-in person asked p.stonn to send
// to someone they chose. The sender's address is shown: a recommendation from a
// stranger is worth nothing, and they picked the recipient.
func (s *Service) SendReferralInvite(ctx context.Context, to, sender string) error {
	if !s.mail.Enabled() {
		return nil
	}
	subject := sender + " thought you might like p.stonn"
	body := strings.Join([]string{
		say(s.tenantOf(ctx, sender), "mail.referral_lead", map[string]any{"Sender": sender}),
		"",
		say(s.tenantOf(ctx, sender), "mail.referral_body", nil),
		"",
		"Have a look: https://p.stonn.org",
		"",
		"If you weren't expecting this, you can ignore it — nothing else will be sent.",
	}, "\n")
	return s.sendEmail(ctx, to, subject, body, reasonReferral)
}
