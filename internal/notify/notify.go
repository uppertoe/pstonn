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
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/store"
)

// councilPortalURL is the council's self-service permit portal, linked in
// failure and re-link notices so a user can set their permit's vehicle
// themselves (and avoid a fine) when p.stonn can't.
const councilPortalURL = "https://parkingpermits.stonnington.vic.gov.au/"

// Service dispatches notifications according to each user's stored preferences.
type Service struct {
	store      *store.Store
	mail       *mailer.Mailer
	ntfyBase   string
	ntfyToken  string
	appURL     string         // public base URL, linked in messages
	adminEmail string         // operator alert address (systemic failures)
	adminTopic string         // operator alert ntfy topic
	loc        *time.Location // display timezone, for interpreting quiet-hours settings
	http       *http.Client
}

// New builds a Service. mail may be nil (email disabled); ntfyBase may be empty
// (push disabled). adminEmail/adminTopic receive operator alerts (either may be
// empty).
func New(st *store.Store, m *mailer.Mailer, ntfyBase, ntfyToken, appURL, adminEmail, adminTopic string, loc *time.Location) *Service {
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
	}
}

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

// NotifyRelinkRequired tells the user their council connection dropped and they
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
	body += "\nCouncil portal: " + councilPortalURL
	// Tell EVERYONE on the account (owner + secondaries) -- a lapsed council
	// connection can land the whole household a fine, and secondaries help manage
	// the permit. Re-link is important, so always email each member's verified
	// address (channel opt-outs don't apply); push to each member's topic too.
	members, err := s.store.AccountEmails(ctx, owner)
	if err != nil {
		members = []string{owner}
	}
	delivered := 0
	for _, m := range members {
		mpref, _ := s.store.GetNotifyPref(ctx, m)
		if s.mail.Enabled() {
			if e := s.mail.Send(m, subject, body); e != nil {
				log.Printf("notify relink email %s: %v", m, e)
			} else {
				delivered++
			}
		}
		if mpref.NtfyEnabled && s.ntfyBase != "" && mpref.NtfyTopic != "" {
			if e := s.sendNtfy(ctx, mpref.NtfyTopic, subject, body, "high", "warning"); e != nil {
				log.Printf("notify relink ntfy %s: %v", m, e)
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
	body += "\nRenew with the council: " + councilPortalURL
	dels, err := s.accountDeliveries(ctx, owner)
	if err != nil {
		return 0
	}
	delivered := 0
	now := time.Now()
	for _, d := range dels {
		wantEmail := d.pref.EmailEnabled && s.mail.Enabled()
		wantNtfy := d.pref.NtfyEnabled && s.ntfyBase != "" && d.pref.NtfyTopic != ""
		if !wantEmail && !wantNtfy {
			continue
		}
		// This is a routine reminder (its own wording says so), not an emergency:
		// honour the member's quiet hours by holding it in the outbox — the
		// expiry-sync runs on the keep-warm cadence at arbitrary times, and a
		// 14-days-ahead warning must not ping anyone at 3am. Queuing counts as
		// reached (the outbox retries it from here).
		if nb := s.quietDefer(d.pref, now); !nb.IsZero() {
			m := outMessage{
				Account: owner, Subject: subject, Body: body,
				NtfyPriority: "default", NtfyTag: "calendar", NotBefore: nb,
				DedupKey: fmt.Sprintf("expiry|%s|%s|%s", owner, permitLabel, date),
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
			if e := s.mail.Send(d.email, subject, body); e != nil {
				log.Printf("notify permit-expiry email %s: %v", d.email, e)
			} else {
				reached = true
			}
		}
		if wantNtfy {
			if e := s.sendNtfy(ctx, d.pref.NtfyTopic, subject, body, "default", "calendar"); e != nil {
				log.Printf("notify permit-expiry ntfy %s: %v", d.email, e)
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
func (s *Service) SendRenewalReminder(to string, deadline time.Time, confirmURL string) error {
	return s.mail.SendRenewalReminder(to, deadline, confirmURL)
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
	Source      string // "roster" / "override" / "guest" (success context)
	OK          bool
	CurrentReg  string // what is still on the permit on failure ("" if unknown)
	Reason      string // one plain sentence: why it failed
	Action      string // one plain sentence: what the user should do
	Transient   bool   // failure expected to self-heal → soften wording

	// DisplacedReg is the plate of a still-live third-party booking this change
	// bumped off the permit ("" when nothing of note was displaced), and
	// DisplacedTold whether its driver got their own heads-up email. When they
	// couldn't be reached, the account notification asks the members to relay
	// the warning — otherwise the displaced car sits uncovered with nobody told.
	DisplacedReg  string
	DisplacedTold bool
}

// actionNeeded reports a hard failure the user must act on (a non-transient
// error: a dead council session, a rejected plate). These bypass the quiet-hours
// hold and send immediately — an unattended fine risk shouldn't wait until 6am.
func (o ApplyOutcome) actionNeeded() bool { return !o.OK && !o.Transient }

// deferUntil returns the quiet-hours delivery time for this outcome, or the zero
// time (send now) when the outcome is a hard action-needed failure.
func (s *Service) deferUntil(pref store.NotifyPref, now time.Time, o ApplyOutcome) time.Time {
	if o.actionNeeded() {
		return time.Time{}
	}
	return s.quietDefer(pref, now)
}

// composeApply builds the subject/body/priority/tags for an apply notification,
// shared by the inline NotifyApply (scheduler) and the durable EnqueueApply.
func composeApply(o ApplyOutcome) (subject, body, priority, tags string) {
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
		case o.By != "":
			body = fmt.Sprintf("Your %s is now set to %s.\n\n%s activated it with a guest link, so it overrides your schedule until that booking ends — then your roster takes over again.",
				o.PermitLabel, car, o.By)
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
		switch {
		case o.CurrentReg != "" && o.Transient:
			subject = fmt.Sprintf("Still updating your %s — it shows %s for now", o.PermitLabel, o.CurrentReg)
		case o.CurrentReg != "":
			subject = fmt.Sprintf("Action needed: your %s still shows %s", o.PermitLabel, o.CurrentReg)
		case o.Transient:
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
		// A failure is a "sort it yourself" moment: link the council portal.
		lines = append(lines, "", "You can set the vehicle on your permit yourself at the council:", councilPortalURL)
		body = strings.Join(lines, "\n")
	}
	priority, tags = "default", "white_check_mark"
	if !o.OK {
		tags = "warning"
		if o.Transient {
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
	subject, body, priority, tags := composeApply(o)
	if s.appURL != "" {
		body += "\n\n" + s.appURL
	}
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
		}
		if d.pref.EmailEnabled && s.mail.Enabled() {
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
	subject, body, priority, tags := composeApply(o)
	emailBody := body
	if s.appURL != "" {
		emailBody += "\n\n" + s.appURL
	}
	var errs []string
	due := 0 // members with at least one channel that should have received this
	now := time.Now()
	for _, d := range dels {
		if o.OK && d.pref.FailuresOnly {
			continue
		}
		wantEmail := d.pref.EmailEnabled && s.mail.Enabled()
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
			if e := s.mail.Send(d.email, subject, emailBody); e != nil {
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
		if e := s.mail.Send(user, subject, body); e != nil {
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

// NotifyDisconnected tells the user their council account was disconnected,
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
		if e := s.mail.Send(owner, subject, body); e != nil {
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
func (s *Service) SendInvite(to, ownerEmail string) error {
	if !s.mail.Enabled() {
		return nil
	}
	subject := "You have been given access to a p.stonn account"
	lines := []string{
		ownerEmail + " has given you shared access to their p.stonn account, which schedules a City of Stonnington visitor parking permit.",
		"",
		"Sign in with this email address to help manage the schedule. You will get a one-time code to confirm it is you.",
	}
	if s.appURL != "" {
		lines = append(lines, "", s.appURL)
	}
	lines = append(lines,
		"",
		"If you were not expecting this, you can ignore this email. You can also remove your access from Settings after signing in.")
	return s.mail.Send(to, subject, strings.Join(lines, "\n"))
}

// SendGuestLink emails a recipient their personal guest-pass link (email only,
// no-op without SMTP). The link lets them set one of the account's cars on the
// visitor permit without an account of their own.
func (s *Service) SendGuestLink(to, ownerEmail, permitLabel, url string) error {
	if !s.mail.Enabled() {
		return nil
	}
	subject := "Your link to set a car on " + ownerEmail + "'s parking permit"
	lines := []string{
		ownerEmail + " has given you a link to put a car on their City of Stonnington visitor parking permit (" + permitLabel + ").",
		"",
		"When you arrive, open the link and choose your car. It stays on the permit until the end of the day.",
		"",
		url,
		"",
		"Tip: bookmark this link or add it to your phone's home screen — then next time you can open it in one tap, without hunting for this email. The same link works every time.",
		"",
		"Keep this link to yourself. If you were not expecting it, you can ignore this email.",
	}
	return s.mail.Send(to, subject, strings.Join(lines, "\n"))
}

// NotifyDriverDisplaced warns whoever is responsible for a displaced car (the
// guest who booked it, or the saved vehicle's attached driver — someone with no
// account, so email only) that the car is no longer on the permit, so they can
// move it or get it put back before getting caught out. No-op without SMTP.
func (s *Service) NotifyDriverDisplaced(ctx context.Context, owner, to, permitLabel, oldReg, newReg string) error {
	if !s.mail.Enabled() {
		return nil
	}
	subject := fmt.Sprintf("Heads up: %s is no longer on the %s", oldReg, permitLabel)
	lines := []string{
		fmt.Sprintf("%s is no longer the car covered by the visitor permit (%s).", oldReg, permitLabel),
		fmt.Sprintf("The permit now shows %s instead.", newReg),
		"",
		fmt.Sprintf("If %s is still parked there, please move it — or put it back on the permit (with your link, or by asking the permit holder) so you stay covered.", oldReg),
	}
	return s.enqueue(ctx, outMessage{Account: owner, Recipients: []string{to}, Subject: subject, Body: strings.Join(lines, "\n")})
}

// NotifyGuestRequest tells the account (all members) that someone scanned a
// printed QR and is asking to put a plate on the permit, so they can approve or
// decline it in the app. Each member is nudged on the channels THEY chose (the
// EnqueueApply pattern) — a push-only secondary gets the push on their own
// topic, not silence. Two deliberate departures from the apply pattern:
// failures-only does not apply (this is a question, not an outcome), and quiet
// hours are NOT honoured — the visitor is standing at the door now, and the
// request expires unanswered within the hour.
func (s *Service) NotifyGuestRequest(ctx context.Context, owner, permitLabel, plate, url string) error {
	subject := fmt.Sprintf("Approve %s on your %s?", plate, permitLabel)
	lines := []string{
		fmt.Sprintf("Someone at your door scanned your printed QR and is asking to put %s on your %s.", plate, permitLabel),
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
			// Per-member key (then per-target suffix in enqueueSplit): a re-scan of
			// the same plate while the first nudge is still fresh doesn't re-notify
			// anyone, and one member's rows never dedup away another member's.
			DedupKey: fmt.Sprintf("guestreq|%s|%s|%s|%s", d.email, owner, permitLabel, plate),
		}
		if d.pref.EmailEnabled && s.mail.Enabled() {
			m.Recipients = []string{d.email}
		}
		if d.pref.NtfyEnabled && s.ntfyBase != "" && d.pref.NtfyTopic != "" {
			m.NtfyTopic = d.pref.NtfyTopic
		}
		if len(m.Recipients) == 0 && m.NtfyTopic == "" {
			continue // this member opted out of every channel
		}
		if e := s.enqueueSplit(ctx, m); e != nil {
			errs = append(errs, d.email+": "+e.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("guest request notify: %s", strings.Join(errs, "; "))
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
}

func (s *Service) enqueue(ctx context.Context, m outMessage) error {
	return s.store.EnqueueOutbox(ctx, store.OutboxItem{
		Account: m.Account, DedupKey: m.DedupKey, Recipients: m.Recipients, NtfyTopic: m.NtfyTopic,
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
			if _, err := s.store.PurgeSentOutbox(ctx, time.Now().Add(-7*24*time.Hour)); err != nil {
				log.Printf("notify: purge outbox: %v", err)
			}
		}
	}
}

func (s *Service) drainOutbox(ctx context.Context) {
	due, err := s.store.DueOutbox(ctx, time.Now(), outboxBatch)
	if err != nil {
		log.Printf("notify: read outbox: %v", err)
		return
	}
	for _, it := range due {
		if ctx.Err() != nil {
			return
		}
		lastErr := s.deliver(ctx, it)
		if lastErr == "" {
			_ = s.store.MarkOutboxSent(ctx, it.ID)
			continue
		}
		attempts := it.Attempts + 1
		if attempts >= outboxMaxAttempts {
			_ = s.store.MarkOutboxDead(ctx, it.ID, lastErr)
			// Always log the drop (the DB 'dead' row is otherwise unsurfaced), and
			// log if the escalation itself fails — it uses NotifyAdmin, which may
			// share the very channel that's failing.
			log.Printf("notify: DROPPED after %d attempts: %q to %v: %s", attempts, it.Subject, it.Recipients, lastErr)
			if ae := s.NotifyAdmin(ctx, "Notification undeliverable (gave up)",
				fmt.Sprintf("A notification could not be delivered after %d attempts and was dropped.\nSubject: %s\nTo: %s\nLast error: %s",
					attempts, it.Subject, strings.Join(it.Recipients, ", "), lastErr)); ae != nil {
				log.Printf("notify: dead-letter admin alert also failed: %v", ae)
			}
			continue
		}
		_ = s.store.RescheduleOutbox(ctx, it.ID, attempts, time.Now().Add(outboxBackoff(attempts)), lastErr)
	}
}

// deliver attempts every channel and returns "" if at least one accepted (or there
// was nothing addressable), else a joined error so the item is retried.
func (s *Service) deliver(ctx context.Context, it store.OutboxItem) string {
	var errs []string
	// Email is the reliable channel. When the message HAS email recipients, success
	// requires at least one email to be accepted — an ntfy 200 (which the server
	// returns even with no subscriber) must not mask a total email failure and
	// silently drop the account's email. When there is no email, ntfy gates.
	emailTargets, emailOK := 0, false
	if s.mail.Enabled() {
		for _, addr := range it.Recipients {
			emailTargets++
			if e := s.mail.Send(addr, it.Subject, it.Body); e != nil {
				errs = append(errs, "email "+addr+": "+e.Error())
			} else {
				emailOK = true
			}
		}
	}
	ntfyTargets, ntfyOK := 0, false
	if it.NtfyTopic != "" && s.ntfyBase != "" {
		ntfyTargets++
		pr := it.NtfyPriority
		if pr == "" {
			pr = "default"
		}
		if e := s.sendNtfy(ctx, it.NtfyTopic, it.Subject, it.Body, pr, it.NtfyTag); e != nil {
			errs = append(errs, "ntfy: "+e.Error())
		} else {
			ntfyOK = true
		}
	}
	switch {
	case emailTargets > 0:
		if emailOK {
			return "" // reached via the reliable channel (ntfy is a bonus on top)
		}
	case ntfyTargets > 0:
		if ntfyOK {
			return "" // no email configured; ntfy was all we had and it worked
		}
	default:
		return "" // nothing addressable (all channels off) — nothing to retry
	}
	return strings.Join(errs, "; ")
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
