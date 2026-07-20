// Package mailer sends the app's transactional email over SMTP. It is optional:
// when SMTP is not configured the constructor returns nil and callers simply skip
// sending (mirroring the OIDC-optional pattern elsewhere).
package mailer

import (
	"fmt"
	"net/smtp"
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
	}
	if replyTo != "" {
		headers = append(headers, "Reply-To: "+headerValue(replyTo))
	}
	headers = append(headers,
		"Subject: "+headerValue(subject),
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
	return smtp.SendMail(m.addr, m.auth, senderAddress(m.from), []string{to}, []byte(b.String()))
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
