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
	"encoding/hex"
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

// NotifyApply tells the permit owner that a plate change was applied (ok=true)
// or failed, honouring their channel choices and "failures only" setting. It
// returns how many channels ACCEPTED the message: the caller uses 0 to mean
// "the user was NOT reached" so it can escalate to the operator and retry, rather
// than silently marking the outcome as delivered.
func (s *Service) NotifyApply(ctx context.Context, owner, permitLabel, reg, source string, ok bool, detail string) (delivered int, err error) {
	pref, err := s.store.GetNotifyPref(ctx, owner)
	if err != nil {
		return 0, err
	}
	// "Failures only": suppress success notices, but never suppress failures.
	if ok && pref.FailuresOnly {
		return -1, nil // -1: intentionally not sent (not a delivery failure)
	}
	var subject, body string
	if ok {
		subject = fmt.Sprintf("Permit updated: %s is now %s", permitLabel, reg)
		body = fmt.Sprintf("Your %s has been set to %s (%s).", permitLabel, reg, source)
	} else {
		subject = fmt.Sprintf("Permit change FAILED: %s", permitLabel)
		body = fmt.Sprintf("Could not set %s to %s.\n\n%s\n\nOpen the app to check your council connection.", permitLabel, reg, detail)
	}

	var errs []string
	if pref.EmailEnabled && s.mail.Enabled() {
		emailBody := body
		if s.appURL != "" {
			emailBody += "\n\n" + s.appURL
		}
		if e := s.mail.Send(owner, subject, emailBody); e != nil {
			errs = append(errs, "email: "+e.Error())
		} else {
			delivered++
		}
	}
	if pref.NtfyEnabled && s.ntfyBase != "" && pref.NtfyTopic != "" {
		priority, tags := "default", "white_check_mark"
		if !ok {
			priority, tags = "high", "warning"
		}
		if e := s.sendNtfy(ctx, pref.NtfyTopic, subject, body, priority, tags); e != nil {
			errs = append(errs, "ntfy: "+e.Error())
		} else {
			delivered++
		}
	}
	if len(errs) > 0 {
		return delivered, fmt.Errorf("notify %s: %s", owner, strings.Join(errs, "; "))
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
		if e := s.mail.Send(owner, subject, body); e != nil {
			errs = append(errs, "email: "+e.Error())
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
func RandomTopic() string {
	b := make([]byte, 9)
	_, _ = crand.Read(b)
	return "pstonn-" + hex.EncodeToString(b)
}
