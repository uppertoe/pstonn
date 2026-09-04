package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/store"
)

// RedactEmail and redactEmails are thin wrappers over the shared redact package,
// kept so notify's many existing callers don't churn. The reasoning (logs are
// the leakiest surface, the full address stays in the DB) now lives in redact.
func RedactEmail(a string) string       { return redact.Email(a) }
func redactEmails(list []string) string { return redact.Emails(list) }

// errText renders a send error for a joined error string or last_error column,
// with the recipient scrubbed out of the server's own words. The mailer wraps
// the SMTP reply verbatim, and a rejection at RCPT TO routinely echoes the
// address ("550 5.1.1 <a@b.com>: user unknown"), so redacting only the prefix we
// add ourselves still left the full address in the log the caller %v's.
func errText(e error, addrs ...string) string {
	if e == nil {
		return ""
	}
	return redact.InText(e.Error(), addrs...)
}

// sendEmail is the single choke point for user-facing email. It refuses to send
// to an address the provider has told us is dead or that complained, and it
// records a permanent SMTP refusal as a new suppression so the next send skips
// it rather than repeating the damage.
//
// Operator alerts deliberately do NOT go through here: if the operator's own
// address bounces we still want every future attempt made (and the failure
// logged), rather than the app quietly muting its own alarm channel.
func (s *Service) sendEmail(ctx context.Context, to, subject, body, reason string) error {
	return s.sendEmailWith(ctx, to, subject, body, reason, false, mailer.Hero{})
}

// sendEmailCritical is sendEmail for safety-critical mail: messages whose miss
// can cost the household a fine (an action-needed apply failure, a re-link
// prompt, a stalled reconnect, a disconnection). A recipient's own unsubscribe
// does not stop these — unsubscribing opts out of the routine notification
// stream, not of being told their permit is no longer being managed, and the
// unsubscribe page says exactly that. A bounce or a complaint still blocks:
// those addresses are dead or asked-us-to-stop-via-their-provider, and mailing
// them anyway damages deliverability for every user of the sending domain.
//
// A critical message that is QUEUED rather than sent inline (a permit-expiry
// warning held for quiet hours, a guest-activation failure routed through
// EnqueueApply) carries the same flag on its outbox row, so deliver() applies
// the same rule when the row comes due. Without that the hold quietly demoted
// the message: sent at 9pm it would reach an unsubscribed member, sent at 11pm
// it would not.
func (s *Service) sendEmailCritical(ctx context.Context, to, subject, body, reason string) error {
	return s.sendEmailWith(ctx, to, subject, body, reason, true, mailer.Hero{})
}

func (s *Service) sendEmailWith(ctx context.Context, to, subject, body, reason string, critical bool, hero mailer.Hero) error {
	return s.sendEmailAs(ctx, to, "", to, subject, body, reason, critical, hero)
}

// sendEmailAs is sendEmailWith for a recipient whose tenant is that of
// tenantOwner (a guest or invitee has no account; the owner who reached them
// does), narrowed to tenantID when the mail concerns one permit.
func (s *Service) sendEmailAs(ctx context.Context, tenantOwner, tenantID, to, subject, body, reason string, critical bool, hero mailer.Hero) error {
	if !s.mail.Enabled() {
		return nil
	}
	if s.store != nil {
		if bad, why, err := s.store.IsSuppressed(ctx, to); err != nil {
			// Fail OPEN: a lookup error must not stop a permit notification going out.
			alog.Infof("suppression lookup for %s: %v", RedactEmail(to), err)
		} else if bad {
			if !(critical && why == store.SuppressUnsubscribed) {
				return fmt.Errorf("%w: %s", ErrSuppressed, why)
			}
			alog.Infof("critical notice to unsubscribed %s goes out anyway (unsubscribe mutes routine mail, not safety alerts)", RedactEmail(to))
		}
	}
	c := s.tenantOf(ctx, tenantOwner, tenantID)
	opts := mailer.Options{UnsubscribeURL: s.UnsubscribeURL(to), Footer: say(c, "mail.footer_affiliation", nil), Hero: hero}
	if reason != "" {
		opts.Provenance = say(c, "mail.provenance", map[string]any{"To": to, "Reason": reason})
	}
	err := s.mail.SendOpts(to, subject, body, opts)
	// Only a REJECTED RECIPIENT earns a suppression. A permanent failure at MAIL
	// FROM or DATA says something is wrong with us or the message, not with this
	// mailbox, and acting on it would blacklist every user we tried to reach.
	if err != nil && errors.Is(err, mailer.ErrBadAddress) && s.store != nil {
		if serr := s.store.SuppressAddress(ctx, to, store.SuppressBounce, err.Error()); serr != nil {
			alog.Infof("suppress %s: %v", RedactEmail(to), serr)
		} else {
			// The full address and the server's own diagnostic go in the suppression
			// row, which is where an operator looks and which gets pruned; the log line
			// only needs to say that it happened.
			alog.Errorf("suppressing %s after the mail server rejected the address", RedactEmail(to))
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
