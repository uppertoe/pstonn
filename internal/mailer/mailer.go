// Package mailer sends the app's transactional email over SMTP. It is optional:
// when SMTP is not configured the constructor returns nil and callers simply skip
// sending (mirroring the OIDC-optional pattern elsewhere).
package mailer

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
)

// Mailer sends email via an SMTP submission server (STARTTLS on the configured
// port, PLAIN auth when a username is set).
type Mailer struct {
	host string
	addr string
	auth smtp.Auth
	from string
}

// New returns a Mailer, or nil when email is not configured. A nil *Mailer is
// safe: its methods are no-ops, so callers need not branch.
func New(cfg config.SMTPConfig) *Mailer {
	if !cfg.Enabled() {
		return nil
	}
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	return &Mailer{
		host: cfg.Host,
		addr: fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		auth: auth,
		from: cfg.From,
	}
}

// Enabled reports whether email will actually be sent.
func (m *Mailer) Enabled() bool { return m != nil }

// SendRenewalReminder emails one user the "confirm you're still using this" note
// with a single-click link. deadline is when the session would otherwise stop.
func (m *Mailer) SendRenewalReminder(to string, deadline time.Time, confirmURL string) error {
	if m == nil {
		return nil
	}
	when := deadline.Format("Monday 2 January 2006")
	subject := "Keep your Stonnington parking scheduler running"
	body := strings.Join([]string{
		"Hi,",
		"",
		"Your visitor-permit scheduler is still running and updating your permit automatically.",
		"",
		"As a periodic safety check that you're still using it, please confirm you'd like it to keep going. If you do nothing, it will stop on " + when + " and you'll need to link your council account again.",
		"",
		"Confirm and keep it running (one click):",
		confirmURL,
		"",
		"If you no longer want the service, just ignore this email and it will stop on its own.",
		"",
		"-- p.stonn",
	}, "\r\n")
	return m.send(to, "", subject, body)
}

// Send delivers a plain-text email. A nil *Mailer is a no-op.
func (m *Mailer) Send(to, subject, body string) error {
	if m == nil {
		return nil
	}
	return m.send(to, "", subject, body)
}

// SendWithReplyTo is Send with a Reply-To header, so a reply reaches the
// submitter rather than the From address (used by the contact form). replyTo is
// ignored when empty. A nil *Mailer is a no-op.
func (m *Mailer) SendWithReplyTo(to, replyTo, subject, body string) error {
	if m == nil {
		return nil
	}
	return m.send(to, replyTo, subject, body)
}

// emailBoundary separates the two MIME parts. A fixed, unlikely token is fine for
// transactional mail (both parts are base64-encoded, so it can't appear in a body).
const emailBoundary = "==_pstonn_alt_b19c7f42a8=="

func (m *Mailer) send(to, replyTo, subject, body string) error {
	headers := []string{
		"From: " + headerValue(m.from),
		"To: " + headerValue(to),
		// Date and Message-ID are mandatory (RFC 5322 §3.6). Not every relay
		// backfills them, and spam filters score their absence — for a domain with
		// no sending history that alone can land transactional mail in Junk.
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: " + messageID(m.from),
		// These are machine-generated notices: tell mail systems so, so that
		// auto-responders and vacation replies don't bounce back at us.
		"Auto-Submitted: auto-generated",
	}
	if replyTo != "" {
		headers = append(headers, "Reply-To: "+headerValue(replyTo))
	}
	headers = append(headers,
		// Q-encode the subject when it contains non-ASCII (RFC 2047): permit and
		// vehicle names flow in here, and a raw 8-bit header mojibakes in some
		// clients. ASCII subjects pass through unchanged.
		"Subject: "+mime.QEncoding.Encode("utf-8", headerValue(subject)),
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="`+emailBoundary+`"`,
	)
	// multipart/alternative: a plain-text part (the source of truth, always shown
	// by text-only clients) plus a branded HTML part. Both base64-encoded so long
	// lines and any UTF-8 are transmitted intact.
	var b strings.Builder
	b.WriteString(strings.Join(headers, "\r\n"))
	b.WriteString("\r\n\r\n")
	b.WriteString("--" + emailBoundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(b64Wrap(body) + "\r\n")
	b.WriteString("--" + emailBoundary + "\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(b64Wrap(htmlDocument(subject, body)) + "\r\n")
	b.WriteString("--" + emailBoundary + "--\r\n")
	return m.deliver(to, []byte(b.String()))
}

// How long one complete SMTP exchange (dial through QUIT) may take. Sends run
// synchronously inside the scheduler's keep-warm pass and the outbox worker, so
// a server that accepts the connection and then stalls must not be able to hold
// those loops hostage — net/smtp.SendMail sets no deadlines at all.
// A var so tests can shorten it.
var smtpExchangeTimeout = 30 * time.Second

// deliver speaks SMTP with an overall wall-clock deadline covering every read
// and write. Semantics mirror smtp.SendMail: EHLO, STARTTLS when offered, auth
// when configured and offered, then MAIL/RCPT/DATA/QUIT. PLAIN auth still
// refuses to run over plaintext (smtp.PlainAuth enforces TLS-or-localhost).
func (m *Mailer) deliver(to string, msg []byte) error {
	// smtp.SendMail validates these to block SMTP command injection; keep that.
	if strings.ContainsAny(to, "\r\n") {
		return errors.New("mailer: recipient contains CR/LF")
	}
	from := senderAddress(m.from)
	if strings.ContainsAny(from, "\r\n") {
		return errors.New("mailer: sender contains CR/LF")
	}
	conn, err := net.DialTimeout("tcp", m.addr, 10*time.Second)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(smtpExchangeTimeout)); err != nil {
		conn.Close()
		return err
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: m.host}); err != nil {
			return err
		}
	}
	if m.auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(m.auth); err != nil {
				return err
			}
		}
	}
	if err := c.Mail(from); err != nil {
		return classify(err)
	}
	// The recipient is rejected here for a bad/unknown mailbox, which is the
	// failure worth classifying: a 5xx means retrying can never help, and
	// hammering a dead address is what damages a sending domain's reputation.
	if err := c.Rcpt(to); err != nil {
		return classify(err)
	}
	w, err := c.Data()
	if err != nil {
		return classify(err)
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return classify(err)
	}
	return c.Quit()
}

// ErrPermanent marks a send that must never be retried: the server refused it
// with a 5xx, so the address (or the message) is rejected outright. Callers use
// errors.Is to decide between "back off and try again" and "stop, and remember
// this address is undeliverable".
var ErrPermanent = errors.New("permanent SMTP failure")

// classify inspects an SMTP reply and wraps permanent (5xx) refusals with
// ErrPermanent. Transient replies (4xx) and connection-level errors pass through
// unchanged so the existing retry/backoff applies.
//
// 421 is a 4xx and already transient. Note that a 5xx at RCPT is the classic
// "user unknown"; a 5xx at DATA/close is usually the message being refused
// (size, content) rather than the address, but both are futile to retry.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var te *textproto.Error
	if errors.As(err, &te) && te.Code >= 500 && te.Code < 600 {
		return fmt.Errorf("%w: %d %s", ErrPermanent, te.Code, te.Msg)
	}
	return err
}

// headerValue neutralises CR/LF in a value destined for an email header, so
// user-influenced content (e.g. a permit or vehicle name in the Subject) can't
// inject extra headers or body — SMTP header injection.
func headerValue(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// senderAddress extracts the bare address from a possibly-decorated From header
// ("Name <a@b>" → "a@b"); SendMail's envelope-from must be an address only.
func senderAddress(from string) string {
	if i := strings.LastIndex(from, "<"); i >= 0 {
		if j := strings.Index(from[i:], ">"); j >= 0 {
			return from[i+1 : i+j]
		}
	}
	return strings.TrimSpace(from)
}

// messageID builds a globally unique RFC 5322 Message-ID, using the sender's
// domain as the right-hand side so it stays consistent with the From header.
func messageID(from string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Never fail a send over this: a time-based id is still unique enough to
		// serve its purpose (deduplication and threading by receivers).
		return fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), messageIDDomain(from))
	}
	return fmt.Sprintf("<%s@%s>", hex.EncodeToString(b[:]), messageIDDomain(from))
}

// messageIDDomain is the domain part of the sender address, falling back to a
// literal when the configured From has no recognisable domain.
func messageIDDomain(from string) string {
	addr := senderAddress(from)
	if i := strings.LastIndex(addr, "@"); i >= 0 && i+1 < len(addr) {
		if d := strings.TrimSpace(addr[i+1:]); d != "" {
			return d
		}
	}
	return "pstonn.invalid"
}
