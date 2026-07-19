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
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/store"
)

// Service dispatches notifications according to each user's stored preferences.
type Service struct {
	store      *store.Store
	mail       *mailer.Mailer
	ntfyBase   string
	ntfyToken  string
	appURL     string // public base URL, linked in messages
	adminEmail string // operator alert address (systemic failures)
	adminTopic string // operator alert ntfy topic
	http       *http.Client
}

// New builds a Service. mail may be nil (email disabled); ntfyBase may be empty
// (push disabled). adminEmail/adminTopic receive operator alerts (either may be
// empty).
func New(st *store.Store, m *mailer.Mailer, ntfyBase, ntfyToken, appURL, adminEmail, adminTopic string) *Service {
	return &Service{
		store:      st,
		mail:       m,
		ntfyBase:   strings.TrimRight(ntfyBase, "/"),
		ntfyToken:  ntfyToken,
		appURL:     strings.TrimRight(appURL, "/"),
		adminEmail: strings.TrimSpace(adminEmail),
		adminTopic: strings.TrimSpace(adminTopic),
		http:       &http.Client{Timeout: 10 * time.Second},
	}
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
	pref, err := s.store.GetNotifyPref(ctx, owner)
	if err != nil {
		pref = store.NotifyPref{Owner: owner}
	}
	subject := "Action needed: reconnect your p.stonn council account"
	body := "Your council connection has expired, so p.stonn has stopped updating your visitor permit.\n\n" +
		"Please open the app and re-link your council account so your schedule keeps running. " +
		"Until you do, check your permit manually to avoid a fine."
	if s.appURL != "" {
		body += "\n\n" + s.appURL
	}
	delivered := 0
	if s.mail.Enabled() { // re-link is important: always email the verified address
		if e := s.mail.Send(owner, subject, body); e != nil {
			log.Printf("notify relink email %s: %v", owner, e)
		} else {
			delivered++
		}
	}
	if pref.NtfyEnabled && s.ntfyBase != "" && pref.NtfyTopic != "" {
		if e := s.sendNtfy(ctx, pref.NtfyTopic, subject, body, "high", "warning"); e != nil {
			log.Printf("notify relink ntfy %s: %v", owner, e)
		} else {
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
}

// NotifyApply tells the permit owner about an apply outcome, honouring their
// channel choices and "failures only" setting. It returns how many channels
// ACCEPTED the message: the caller uses 0 to mean "the user was NOT reached" so
// it can escalate to the operator and retry, rather than silently marking the
// outcome as delivered. -1 means intentionally not sent (failures-only success).
func (s *Service) NotifyApply(ctx context.Context, o ApplyOutcome) (delivered int, err error) {
	pref, err := s.store.GetNotifyPref(ctx, o.Owner)
	if err != nil {
		return 0, err
	}
	if o.OK && pref.FailuresOnly {
		return -1, nil
	}

	// "car" names the vehicle we set, by friendly name + plate where we have both,
	// so the subject line tells the reader what is on the permit at a glance.
	car := o.Reg
	if o.Name != "" {
		car = fmt.Sprintf("%s (%s)", o.Name, o.Reg)
	}
	var subject, body string
	if o.OK {
		subject = fmt.Sprintf("Permit updated: %s now shows %s", o.PermitLabel, car)
		body = fmt.Sprintf("Your %s has been set to %s (%s).", o.PermitLabel, car, o.Source)
		if o.By != "" {
			// A guest activated it via their link; tell the holder who, and that it
			// overrides the schedule only until it ends (then the roster resumes).
			body += fmt.Sprintf("\n\nActivated by %s using a guest link. This overrides your schedule until it ends, then your roster resumes.", o.By)
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
			lines = append(lines, fmt.Sprintf("Right now the permit still shows %s, so that is the vehicle currently covered.", o.CurrentReg))
		} else {
			lines = append(lines, "The vehicle on the permit has not been changed.")
		}
		if o.Reason != "" {
			lines = append(lines, "", o.Reason)
		}
		if o.Action != "" {
			lines = append(lines, o.Action)
		}
		body = strings.Join(lines, "\n")
	}

	priority, tags := "default", "white_check_mark"
	if !o.OK {
		tags = "warning"
		if o.Transient {
			priority = "default"
		} else {
			priority = "high"
		}
	}

	var errs []string
	if pref.EmailEnabled && s.mail.Enabled() {
		emailBody := body
		if s.appURL != "" {
			emailBody += "\n\n" + s.appURL
		}
		// Email every member of the account (owner plus any secondaries), so a
		// shared household all hear about a change. The account counts as reached
		// (delivered) if at least one member's email is accepted; a single bad
		// address does not force endless retries or an operator alert.
		recipients, _ := s.store.AccountEmails(ctx, o.Owner)
		sent := 0
		for _, addr := range recipients {
			if e := s.mail.Send(addr, subject, emailBody); e != nil {
				errs = append(errs, "email "+addr+": "+e.Error())
			} else {
				sent++
			}
		}
		if sent > 0 {
			delivered++
		}
	}
	if pref.NtfyEnabled && s.ntfyBase != "" && pref.NtfyTopic != "" {
		// One account push topic that any member can subscribe their own device to.
		if e := s.sendNtfy(ctx, pref.NtfyTopic, subject, body, priority, tags); e != nil {
			errs = append(errs, "ntfy: "+e.Error())
		} else {
			delivered++
		}
	}
	if len(errs) > 0 {
		return delivered, fmt.Errorf("notify %s: %s", o.Owner, strings.Join(errs, "; "))
	}
	return delivered, nil
}

// SendTest sends a "notifications are working" message on every enabled channel,
// so the user can confirm their setup from the UI.
func (s *Service) SendTest(ctx context.Context, owner string) error {
	pref, err := s.store.GetNotifyPref(ctx, owner)
	if err != nil {
		return err
	}
	const subject = "p.stonn test notification"
	const body = "This is a test. Your permit-change notifications are set up correctly."
	var errs []string
	if pref.EmailEnabled && s.mail.Enabled() {
		recipients, _ := s.store.AccountEmails(ctx, owner)
		for _, addr := range recipients {
			if e := s.mail.Send(addr, subject, body); e != nil {
				errs = append(errs, "email "+addr+": "+e.Error())
			}
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
		"Keep this link to yourself. If you were not expecting it, you can ignore this email.",
	}
	return s.mail.Send(to, subject, strings.Join(lines, "\n"))
}

// NotifyGuestDisplaced tells a guest (who has no account, so email only) that
// the car they put on a permit via their link has since been taken off it, so
// they can move it or re-activate before getting caught out. No-op without SMTP.
func (s *Service) NotifyGuestDisplaced(ctx context.Context, to, permitLabel, oldReg, newReg string) error {
	if !s.mail.Enabled() {
		return nil
	}
	subject := fmt.Sprintf("Heads up: %s is no longer on the %s", oldReg, permitLabel)
	lines := []string{
		fmt.Sprintf("The car you put on the visitor permit (%s) has just been taken off it.", oldReg),
		fmt.Sprintf("The permit now shows %s instead.", newReg),
		"",
		"If your car is still parked there, please move it or open your link again to put it back on, so you stay covered.",
	}
	return s.mail.Send(to, subject, strings.Join(lines, "\n"))
}

// NotifyGuestRequest tells the account (all members) that someone scanned a
// printed QR and is asking to put a plate on the permit, so they can approve or
// decline it in the app. Goes to every enabled channel.
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

	var errs []string
	if s.mail.Enabled() {
		recipients, _ := s.store.AccountEmails(ctx, owner)
		for _, addr := range recipients {
			if e := s.mail.Send(addr, subject, body); e != nil {
				errs = append(errs, "email "+addr+": "+e.Error())
			}
		}
	}
	if s.ntfyBase != "" {
		if pref, e := s.store.GetNotifyPref(ctx, owner); e == nil && pref.NtfyEnabled && pref.NtfyTopic != "" {
			if e := s.sendNtfy(ctx, pref.NtfyTopic, subject, body, "high", "bell"); e != nil {
				errs = append(errs, "ntfy: "+e.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("notify request %s: %s", owner, strings.Join(errs, "; "))
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
