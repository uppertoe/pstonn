package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/store"
)

// NotifyRelinkRequired tells the user their tenant connection dropped and they
// must re-link, so an idle session that lapsed does not silently stop managing
// their permit until they get a fine. Always emails the verified address (if
// email is configured), plus push if enabled. Returns the number of channels
// that accepted the message.
func (s *Service) NotifyRelinkRequired(ctx context.Context, owner, tenantID string) int {
	subject := "Action needed: reconnect your p.stonn council account"
	body := "Your council connection has expired, so p.stonn has stopped updating your visitor permit.\n\n" +
		"Please open the app and re-link your council account so your schedule keeps running. " +
		"Until you do, set your permit's vehicle directly with the council to avoid a fine."
	if s.appURL != "" {
		body += "\n\nRe-link: " + s.appURL
	}
	body += "\nCouncil portal: " + s.tenantOf(ctx, owner, tenantID).Links.Portal
	return s.broadcastAccount(ctx, owner, "relink", subject, body)
}

// NotifyReconnectStalled tells the household p.stonn cannot sign back in to the
// tenant even though their link is still held (a tenant login outage or a
// changed sign-in page), so their schedule is paused until reconnection
// succeeds. Deliberately NOT a re-link prompt: an interactive re-link goes
// through the same broken login flow, so the honest instruction is to manage
// the permit at the tenant directly until service resumes. Returns the number
// of channels that accepted the message.
func (s *Service) NotifyReconnectStalled(ctx context.Context, owner, tenantID string) int {
	subject := "p.stonn can't reach the council — your permit schedule is paused"
	body := "p.stonn's sign-in to the council expired, and it has not been able to sign back in for over an hour. " +
		"Until it can, your visitor permit schedule is NOT being applied.\n\n" +
		"That means any change your schedule should make will not happen: if a different car needs to be on the permit, " +
		"change the vehicle yourself on the council website now, or that car is not covered and can be fined.\n\n" +
		"p.stonn keeps retrying automatically and your schedule resumes on its own once the council accepts the sign-in again. " +
		"If this persists, it will email you again if re-linking becomes necessary."
	body += "\n\nCouncil portal: " + s.tenantOf(ctx, owner, tenantID).Links.Portal
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
				alog.Infof("notify %s email %s: %s", tag, RedactEmail(m), errText(e, m))
			} else {
				delivered++
			}
		}
		if mpref.NtfyEnabled && s.ntfyBase != "" && mpref.NtfyTopic != "" {
			if e := s.sendNtfy(ctx, mpref.NtfyTopic, subject, body, "high", "warning"); e != nil {
				alog.Infof("notify %s ntfy %s: %v", tag, RedactEmail(m), e)
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
func (s *Service) NotifyPermitExpiry(ctx context.Context, owner, tenantID, permitLabel string, expiry time.Time) int {
	date := expiry.Format("2 Jan 2006")
	subject := fmt.Sprintf("Your %s expires on %s", permitLabel, date)
	body := fmt.Sprintf("Your %s is due to expire on %s.\n\n", permitLabel, date) +
		"p.stonn keeps setting the vehicle, but it can't renew the permit itself — renew it with the council so it stays valid. " +
		"Once you renew, you can copy your schedule onto the new permit in the app."
	if s.appURL != "" {
		body += "\n\nOpen p.stonn: " + s.appURL
	}
	c := s.tenantOf(ctx, owner, tenantID)
	body += "\nRenew with the council: " + c.Links.Portal
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
		if nb := s.quietDefer(d.pref, now, c.Loc); !nb.IsZero() {
			m := outMessage{
				Account: owner, Subject: subject, Body: body,
				NtfyPriority: "default", NtfyTag: "calendar", NotBefore: nb,
				// Keyed on the MEMBER (d.email), not just the account: enqueueSplit
				// suffixes push rows with a bare "|ntfy", so an owner-only key collides
				// across two push-only household members and silently drops the second
				// member's reminder. Every sibling fan-out keys on d.email for this reason.
				DedupKey: fmt.Sprintf("expiry|%s|%s|%s|%s", owner, permitLabel, date, d.email),
				Reason:   reasonAccount,
				// Same tier as the inline send below: the hold must not turn a
				// safety notice into routine mail an unsubscribe can swallow.
				Critical: true,
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
				alog.Infof("notify permit-expiry email %s: %s", RedactEmail(d.email), errText(e, d.email))
			} else {
				reached = true
			}
		}
		if wantNtfy {
			if e := s.sendNtfy(ctx, d.pref.NtfyTopic, subject, body, "default", "calendar"); e != nil {
				alog.Infof("notify permit-expiry ntfy %s: %v", RedactEmail(d.email), e)
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

// SendRenewalReminder is the scheduler's re-authorise reminder (email only).
// It builds its own body in the mailer, so the suppression check is inline here
// rather than via sendEmail.
func (s *Service) SendRenewalReminder(ctx context.Context, to, tenantID string, deadline time.Time, confirmURL string) error {
	if !s.mail.Enabled() {
		return nil
	}
	if s.store != nil {
		if bad, reason, err := s.store.IsSuppressed(ctx, to); err != nil {
			alog.Infof("suppression lookup for %s: %v", RedactEmail(to), err)
		} else if bad {
			return fmt.Errorf("%w: %s", ErrSuppressed, reason)
		}
	}
	// Same envelope obligations as every other person-facing mail: an unsubscribe
	// and a "why you got this".
	c := s.tenantOf(ctx, to, tenantID)
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
			alog.Infof("suppress %s: %v", RedactEmail(to), serr)
		}
	}
	return err
}

// EnqueueApply durably queues an apply notification, for paths with no reconcile-
// loop retry behind them (a guest activation): a failed send is retried by the
// outbox instead of dropped. Enqueues ONE message per account member, each
// honouring that member's own channels + failures-only, and dedups per member so
// a repeated activation of the same plate doesn't double-notify anyone.
// fanoutEnqueue delivers one per-member message to each account member on the
// channels that member enabled, returning how many members were enqueued. build(d)
// returns the message for member d — with its Recipients already set if the caller
// wants this member emailed (the email rule differs by notification type, so the
// caller owns it) — and ok=false to skip the member (a mute the caller owns). This
// helper adds the member's ntfy topic when push is enabled, skips a member left
// with no reachable channel, and enqueues, stopping on the first enqueue error. It
// is the shared spine of the enqueue-one-combined-message notifications; callers
// that send ntfy immediately, split email/push into separate messages, or
// accumulate per-member errors keep their own loop.
func (s *Service) fanoutEnqueue(ctx context.Context, owner string, build func(d memberPref) (outMessage, bool)) (int, error) {
	dels, err := s.accountDeliveries(ctx, owner)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range dels {
		m, ok := build(d)
		if !ok {
			continue
		}
		if d.pref.NtfyEnabled && s.ntfyBase != "" && d.pref.NtfyTopic != "" {
			m.NtfyTopic = d.pref.NtfyTopic
		}
		if len(m.Recipients) == 0 && m.NtfyTopic == "" {
			continue // this member has no reachable channel
		}
		if err := s.enqueueSplit(ctx, m); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (s *Service) EnqueueApply(ctx context.Context, o ApplyOutcome) error {
	c := s.tenantOf(ctx, o.Owner, o.TenantID)
	subject, body, priority, tags := composeApply(o, c.Links.Portal)
	if s.appURL != "" {
		body += "\n\n" + s.appURL
	}
	body += s.firstApplyLine(ctx, o)
	now := time.Now()
	_, err := s.fanoutEnqueue(ctx, o.Owner, func(d memberPref) (outMessage, bool) {
		if o.mutedByFailuresOnly(d.pref) {
			return outMessage{}, false
		}
		m := outMessage{
			Account: o.Owner,
			Subject: subject, Body: body, NtfyPriority: priority, NtfyTag: tags,
			DedupKey:  fmt.Sprintf("apply|%s|%s|%s|%s|%t", d.email, o.Owner, o.PermitLabel, o.Reg, o.OK),
			NotBefore: s.deferUntil(d.pref, now, c.Loc, o),
			Reason:    reasonAccount,
			// The queued twin of NotifyApply's inline choice of sendEmailCritical.
			Critical: o.actionNeeded(),
		}
		if s.emailWanted(d.pref, o) {
			m.Recipients = []string{d.email}
		}
		return m, true
	})
	return err
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
	c := s.tenantOf(ctx, o.Owner, o.TenantID)
	subject, body, priority, tags := composeApply(o, c.Links.Portal)
	emailBody := body
	if s.appURL != "" {
		emailBody += "\n\n" + s.appURL
	}
	emailBody += s.firstApplyLine(ctx, o)
	var errs []string
	due := 0
	var seenKeys []string // every reached-memory key consulted by this delivery
	now := time.Now()
	for _, d := range dels {
		if o.mutedByFailuresOnly(d.pref) {
			continue
		}
		wantEmail := s.emailWanted(d.pref, o)
		wantNtfy := d.pref.NtfyEnabled && s.ntfyBase != "" && d.pref.NtfyTopic != ""
		if !wantEmail && !wantNtfy {
			continue // no reachable channel for this member
		}
		due++

		// A retry of a partial delivery: this member was reached last time, so
		// they still count as delivered, and only the members who were missed are
		// sent to again. Keyed on the caller's outcome identity, so two different
		// notices about the same plate (the soft busy notice and the urgent
		// confirmed-block escalation) are never mistaken for each other.
		seenKey := ""
		if o.Key != "" {
			seenKey = fmt.Sprintf("%s|%d|%s|%s", o.Owner, o.PermitID, o.Key, d.email)
			seenKeys = append(seenKeys, seenKey)
			if s.reached(seenKey, now) {
				delivered++
				continue
			}
		}

		// Quiet hours: hold this member's notice and deliver it via the durable
		// outbox at the window's end, so a midnight roster change lands as a 6am
		// confirmation rather than a 12:01am ping. Queuing counts as reached.
		if nb := s.deferUntil(d.pref, now, c.Loc, o); !nb.IsZero() {
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
				errs = append(errs, "queue "+RedactEmail(d.email)+": "+errText(e, d.email))
			} else {
				delivered++
				if seenKey != "" {
					s.markReached(seenKey, now)
				}
			}
			continue
		}

		// A failure notice past this person's daily budget is dropped, and counted
		// as delivered so the scheduler records the outcome and stops retrying it:
		// they have been told enough today, and the activity page has the rest.
		// Checked here, AFTER the quiet-hours deferral, so only an inline send
		// spends the budget: a deferred notice is deduped in the outbox, and an
		// overnight outage re-attempting every half hour used to burn the whole
		// day's allowance on notices that never went anywhere.
		if !o.OK {
			lim := s.failureTo
			if o.Urgent {
				lim = s.urgentFailureTo
			}
			if !lim.allow(d.email) {
				alog.Infof("apply-failure notice to %s throttled (per-recipient daily cap)", RedactEmail(d.email))
				delivered++
				continue
			}
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
				// Redacted throughout: the caller %v's this error into the log, and a
				// server rejection echoes the address inside e itself.
				errs = append(errs, "email "+RedactEmail(d.email)+": "+errText(e, d.email))
			} else {
				reached = true
			}
		}
		if wantNtfy {
			if e := s.sendNtfy(ctx, d.pref.NtfyTopic, subject, body, priority, tags); e != nil {
				errs = append(errs, "ntfy "+RedactEmail(d.email)+": "+errText(e, d.email))
			} else {
				reached = true
			}
		}
		if reached {
			delivered++
			if seenKey != "" {
				s.markReached(seenKey, now)
			}
		}
	}
	if due == 0 {
		return -1, nil // nobody was due a notification
	}
	if len(errs) > 0 {
		return delivered, fmt.Errorf("notify %s: %s", RedactEmail(o.Owner), strings.Join(errs, "; "))
	}
	// Everyone due was reached, so this delivery is complete and the memory of it
	// must go: it exists only to finish a PARTIAL delivery without repeating
	// itself. Kept past this point it would swallow the next legitimate notice
	// with the same key — the roster re-applying A>B after a resident reverted
	// the plate at the portal, or an urgent session notice that recurs the same
	// day — while the scheduler recorded it as delivered.
	s.forgetReached(seenKeys)
	return delivered, nil
}

// SendTest sends a "notifications are working" message on the acting user's OWN
// enabled channels (their email, their push topic), so each person confirms their
// own setup — a secondary's test doesn't reach the primary and vice versa.
//
// confirmURL, when set, is the endpoint a Confirm button on the PUSH posts back
// to (a one-time token in its path). Tapping it is the only proof p.stonn accepts
// that the push channel works: it shows the message reached a device and was
// seen, which neither a subscription nor a 200 from the ntfy server does (an
// iPhone gets pushes via an APNs relay, and either platform may have the OS
// notification permission denied). The email carries no such button — email is
// the channel this confirmation lets a household turn off.
func (s *Service) SendTest(ctx context.Context, user, confirmURL string) error {
	pref, err := s.store.GetNotifyPref(ctx, user)
	if err != nil {
		return err
	}
	const subject = "p.stonn test notification"
	const body = "This is a test. Your permit-change notifications are set up correctly."
	var errs []string
	if pref.EmailEnabled && s.mail.Enabled() {
		if e := s.sendEmail(ctx, user, subject, body, reasonTest); e != nil {
			errs = append(errs, "email "+RedactEmail(user)+": "+errText(e, user))
		}
	}
	if pref.NtfyEnabled && s.ntfyBase != "" && pref.NtfyTopic != "" {
		if e := s.sendTestPush(ctx, pref.NtfyTopic, confirmURL); e != nil {
			errs = append(errs, "ntfy: "+e.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// SendTestPush sends the test to the acting user's push topic ONLY — the button
// inside the push set-up steps, so someone wiring up their phone is not also
// mailed (and is not blocked by a mail failure). Same Confirm semantics as
// SendTest. ErrNoPush when push is off or unconfigured for them.
func (s *Service) SendTestPush(ctx context.Context, user, confirmURL string) error {
	pref, err := s.store.GetNotifyPref(ctx, user)
	if err != nil {
		return err
	}
	if !pref.NtfyEnabled || s.ntfyBase == "" || pref.NtfyTopic == "" {
		return ErrNoPush
	}
	return s.sendTestPush(ctx, pref.NtfyTopic, confirmURL)
}

func (s *Service) sendTestPush(ctx context.Context, topic, confirmURL string) error {
	const subject = "p.stonn test notification"
	body := "This is a test. Your permit-change notifications are set up correctly."
	var extra map[string]string
	if confirmURL != "" {
		body += " Tap Confirm so p.stonn knows push notifications reach this phone."
		// JSON form of the Actions header: the token is base64 and the
		// comma-separated form would need every '=' escaped. `clear` dismisses
		// the notification once tapped. Click opens Settings, where the result
		// shows, for anyone who taps the body instead of the button.
		extra = map[string]string{
			"Actions": fmt.Sprintf(`[{"action":"http","label":"Confirm","url":%q,"method":"POST","clear":true}]`, confirmURL),
			"Click":   s.appURL + "/settings",
		}
	}
	return s.sendNtfyHeaders(ctx, topic, subject, body, "default", "bell", extra)
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
			errs = append(errs, "email: "+errText(e, owner))
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
		say(s.tenantOf(ctx, ownerEmail, ""), "mail.invite_lead", map[string]any{"Owner": ownerEmail}),
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
	subject, body := onboardNudgeMessage(to, s.appURL, s.tenantOf(ctx, to, ""))
	return s.sendEmail(ctx, to, subject, body, reasonOnboard)
}

// SendGuestLink emails a recipient their personal guest-pass link (email only,
// no-op without SMTP). The link lets them set one of the account's cars on the
// visitor permit without an account of their own.
func (s *Service) SendGuestLink(ctx context.Context, to, ownerEmail, tenantID, permitLabel, url string) error {
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
		say(s.tenantOf(ctx, ownerEmail, tenantID), "mail.guest_lead", map[string]any{"Owner": ownerEmail, "Label": neutraliseLinks(permitLabel)}),
		"",
		"When you arrive, open the link and choose your car. It stays on the permit until the end of the day.",
		"",
		url,
		"",
		"Tip: bookmark this link or add it to your phone's home screen — then next time you can open it in one tap, without hunting for this email. The same link works every time.",
		"",
		"Keep this link to yourself. If you were not expecting it, you can ignore this email.",
		"",
		say(s.tenantOf(ctx, ownerEmail, tenantID), "mail.guest_promo", nil),
	}
	return s.sendEmailAs(ctx, ownerEmail, tenantID, to, subject, strings.Join(lines, "\n"), reasonGuest, false, mailer.Hero{})
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
		alog.Infof("displaced-driver notice to %s throttled (per-recipient cap)", RedactEmail(to))
		return nil
	}
	key := fmt.Sprintf("displaced|%s|%s|%s", to, permitLabel, oldReg)
	return s.enqueue(ctx, outMessage{Account: owner, Recipients: []string{to}, Subject: subject,
		Body: strings.Join(lines, "\n"), DedupKey: key, Reason: reasonDisplace})
}

// NotifyDriverAdded tells a car's driver (a non-user, email only) that their car
// is now ON the permit — reassurance so a nanny/cleaner knows they're covered
// when they arrive. Sent for any add (roster included) when the household left
// the per-car notify toggle on; throttled per recipient and deduped per day so a
// flapping plate can't spam. The one-click unsubscribe + provenance are added by
// the send path from the Reason. No-op without SMTP. The council's name comes
// from the permit's own tenant, so it stays correct across councils.
func (s *Service) NotifyDriverAdded(ctx context.Context, owner, tenantID, to, plate, color string) error {
	if !s.mail.Enabled() {
		return nil
	}
	c := s.tenantOf(ctx, owner, tenantID)
	// The plate leads the subject (and rides the row as a centred chip in the HTML
	// mail), so the body doesn't repeat it \u2014 it just reassures. Blocks are split by
	// blank lines; a "---" block becomes a section separator in the HTML render.
	subject := fmt.Sprintf("%s is on a %s visitor parking permit", plate, c.Short)
	lines := []string{
		fmt.Sprintf("Your car is now on a %s visitor parking permit, so you're covered to park where the permit applies.", c.Name),
		"",
		"---",
		"",
		"This is an automatic note from p.stonn, which the permit holder uses to keep the permit up to date. It's a convenience, not a guarantee \u2014 if you're unsure, check with them.",
	}
	if s.appURL != "" {
		lines = append(lines, "",
			"---",
			"",
			fmt.Sprintf("If you have your own %s visitor parking permit, p.stonn can schedule it for you too \u2014 free.", c.Short),
			s.appURL)
	}
	if !s.driverAddedTo.allow(to) {
		alog.Infof("driver-added notice to %s throttled (per-recipient cap)", RedactEmail(to))
		return nil
	}
	// Deduped per day so a re-add of the same plate the same day is silent.
	key := fmt.Sprintf("driver-on|%s|%s|%s", to, plate, time.Now().In(s.loc).Format("2006-01-02"))
	return s.enqueue(ctx, outMessage{Account: owner, Recipients: []string{to}, Subject: subject,
		Body: strings.Join(lines, "\n"), DedupKey: key, Reason: reasonDriverOn,
		HeroPlate: plate, HeroColor: color})
}

// NotifyDriverFailed tells a car's driver (email only) that their car could not
// be put on the permit, so they know it may not be covered — the failure twin of
// NotifyDriverAdded. The cause is adapted like the household's own notice: a
// council outage says so; anything else stays generic, since the driver can do
// nothing about the detail. Deduped per plate per day and capped per recipient.
func (s *Service) NotifyDriverFailed(ctx context.Context, owner, tenantID, to, plate, color string, councilDown bool) error {
	if !s.mail.Enabled() {
		return nil
	}
	c := s.tenantOf(ctx, owner, tenantID)
	cause := "p.stonn couldn't update the permit"
	if councilDown {
		cause = "the council's system is down right now"
	}
	subject := fmt.Sprintf("%s couldn't be put on a %s visitor parking permit", plate, c.Short)
	lines := []string{
		fmt.Sprintf("Your car %s couldn't be put on the %s visitor parking permit — %s. It may not be covered right now; p.stonn keeps trying and will put it on as soon as it can.", plate, c.Name, cause),
		"",
		"---",
		"",
		"This is an automatic note from p.stonn, which the permit holder uses to keep the permit up to date. It's a convenience, not a guarantee — if you're unsure, check with them.",
	}
	if !s.driverFailedTo.allow(to) {
		alog.Infof("driver-failed notice to %s throttled (per-recipient cap)", RedactEmail(to))
		return nil
	}
	key := fmt.Sprintf("driver-fail|%s|%s|%s", to, plate, time.Now().In(s.loc).Format("2006-01-02"))
	return s.enqueue(ctx, outMessage{Account: owner, Recipients: []string{to}, Subject: subject,
		Body: strings.Join(lines, "\n"), DedupKey: key, Reason: reasonDriverOn,
		HeroPlate: plate, HeroColor: color})
}

// NotifyDriftChanged tells every member of the household that the plate on
// their permit was changed at the council directly — a change p.stonn did not
// make, which may be theirs or may be a surprise. Soft, like a scheduled
// success: quiet hours hold it, and members who only hear about problems are
// skipped (it is information, not a fault). Durable via the outbox, deduped per
// member, permit and plate.
func (s *Service) NotifyDriftChanged(ctx context.Context, owner, tenantID, permitLabel, plate string) error {
	c := s.tenantOf(ctx, owner, tenantID)
	var subject, body string
	if plate == "" {
		subject = fmt.Sprintf("The car was removed from your %s at the council", permitLabel)
		body = fmt.Sprintf("The car on your %s was removed at the council directly — p.stonn didn't make this change. If that wasn't you or someone in your household, you may want to check it.", permitLabel)
	} else {
		subject = fmt.Sprintf("Your %s was changed to %s at the council", permitLabel, plate)
		body = fmt.Sprintf("The car on your %s was changed to %s at the council directly — p.stonn didn't make this change. If that wasn't you or someone in your household, you may want to check it.", permitLabel, plate)
	}
	if s.appURL != "" {
		body += "\n\n" + s.appURL
	}
	now := time.Now()
	_, err := s.fanoutEnqueue(ctx, owner, func(d memberPref) (outMessage, bool) {
		if d.pref.FailuresOnly {
			return outMessage{}, false
		}
		m := outMessage{
			Account: owner, Subject: subject, Body: body,
			DedupKey:  fmt.Sprintf("drift|%s|%s|%s|%s", d.email, owner, permitLabel, plate),
			NotBefore: s.quietDefer(d.pref, now, c.Loc),
			Reason:    reasonAccount,
			HeroPlate: plate,
		}
		if d.pref.EmailEnabled {
			m.Recipients = []string{d.email}
		}
		return m, true
	})
	return err
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
				errs = append(errs, RedactEmail(d.email)+": "+errText(e, d.email))
			}
		}
		if d.pref.NtfyEnabled && s.ntfyBase != "" && d.pref.NtfyTopic != "" {
			pm := m
			pm.NtfyTopic = d.pref.NtfyTopic
			if e := s.enqueueSplit(ctx, pm); e != nil {
				errs = append(errs, RedactEmail(d.email)+": "+errText(e, d.email))
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
	// Account-level: the household's night is the night at their current tenant.
	loc := s.tenantOf(ctx, owner, "").Loc
	var errs []string
	for _, d := range dels {
		if strings.EqualFold(d.email, actor) {
			continue // don't tell someone about their own action
		}
		m := outMessage{
			Account: owner, Subject: subject, Body: body, Reason: reasonAccount,
			NotBefore: s.quietDefer(d.pref, now, loc),
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
			errs = append(errs, RedactEmail(d.email)+": "+errText(e, d.email))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("account change notify: %s", strings.Join(errs, "; "))
	}
	return nil
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
		say(s.tenantOf(ctx, to, ""), "mail.fortnight_line", nil),
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
		say(s.tenantOf(ctx, sender, ""), "mail.referral_lead", map[string]any{"Sender": sender}),
		"",
		say(s.tenantOf(ctx, sender, ""), "mail.referral_body", nil),
		"",
		"Have a look: https://p.stonn.org",
		"",
		"If you weren't expecting this, you can ignore it — nothing else will be sent.",
	}, "\n")
	return s.sendEmail(ctx, to, subject, body, reasonReferral)
}
