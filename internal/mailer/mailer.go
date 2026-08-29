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
	"log"
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

	// SendHook replaces SMTP delivery when set (tests only; see SetSendHook).
	SendHook func(to, subject, body string, o Options) error
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

// Options carries the per-message extras. Zero value = a plain notice.
type Options struct {
	// ReplyTo sets Reply-To, so a reply reaches a submitter rather than the From
	// address (the contact form).
	ReplyTo string
	// UnsubscribeURL adds List-Unsubscribe and RFC 8058 one-click support, plus a
	// visible footer line. REQUIRED on anything sent to a person rather than to
	// the operator: most of our recipients (a guest handed a pass, a driver whose
	// car came off a permit) have no account and no other way to make us stop.
	UnsubscribeURL string
	// Provenance is one plain sentence saying why this address received this
	// message ("Sent to x@y because ..."). Recipients with no account otherwise
	// have no idea who we are or how we got their address.
	Provenance string
	// Footer is the affiliation line under the HTML card ("Not affiliated with
	// the City of X."); the council is the sender's business, not the mailer's.
	Footer string
}

// Send delivers a plain-text email. A nil *Mailer is a no-op.
func (m *Mailer) Send(to, subject, body string) error {
	return m.SendOpts(to, subject, body, Options{})
}

// SendWithReplyTo is Send with a Reply-To header. A nil *Mailer is a no-op.
func (m *Mailer) SendWithReplyTo(to, replyTo, subject, body string) error {
	return m.SendOpts(to, subject, body, Options{ReplyTo: replyTo})
}

// SendOpts delivers a plain-text email with the extras in o. A nil *Mailer is a
// no-op.
func (m *Mailer) SendOpts(to, subject, body string, o Options) error {
	if m == nil {
		return nil
	}
	if m.SendHook != nil {
		return m.SendHook(to, subject, body, o)
	}
	return m.send(to, subject, body, o)
}

// SendHook, when set, receives every message in place of SMTP delivery. It exists
// for the golden email tests (internal/notify), which lock the composed subject,
// body and footer options of every notice the app sends; production never sets it.
func (m *Mailer) SetSendHook(fn func(to, subject, body string, o Options) error) {
	if m != nil {
		m.SendHook = fn
	}
}

// emailBoundary separates the two MIME parts. A fixed, unlikely token is fine for
// transactional mail (both parts are base64-encoded, so it can't appear in a body).
const emailBoundary = "==_pstonn_alt_b19c7f42a8=="

func (m *Mailer) send(to, subject, body string, o Options) error {
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
	if o.ReplyTo != "" {
		headers = append(headers, "Reply-To: "+headerValue(o.ReplyTo))
	}
	if o.UnsubscribeURL != "" {
		// RFC 2369 + RFC 8058. The One-Click header is what makes Gmail/Yahoo show
		// their native "unsubscribe" affordance instead of a "report spam" button —
		// which is the outcome we actually want, since a complaint costs the whole
		// domain's reputation while an unsubscribe costs one address.
		headers = append(headers,
			"List-Unsubscribe: <"+headerValue(o.UnsubscribeURL)+">",
			"List-Unsubscribe-Post: List-Unsubscribe=One-Click")
	}
	headers = append(headers,
		// Q-encode the subject when it contains non-ASCII (RFC 2047): permit and
		// vehicle names flow in here, and a raw 8-bit header mojibakes in some
		// clients. ASCII subjects pass through unchanged.
		"Subject: "+mime.QEncoding.Encode("utf-8", headerValue(subject)),
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="`+emailBoundary+`"`,
	)
	// Footer: who we are, why this address got it, and how to stop. Appended to the
	// plain text so it flows into the HTML part too (htmlDocument derives from it),
	// and so a text-only client sees it identically.
	if o.Provenance != "" || o.UnsubscribeURL != "" {
		var f strings.Builder
		f.WriteString(body)
		f.WriteString("\r\n\r\n--\r\n")
		if o.Provenance != "" {
			f.WriteString(o.Provenance + "\r\n")
		}
		if o.UnsubscribeURL != "" {
			f.WriteString("To stop emails to " + to + ": " + o.UnsubscribeURL + "\r\n")
		}
		body = f.String()
	}
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
	b.WriteString(b64Wrap(htmlDocument(subject, body, o.Footer)) + "\r\n")
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
	// RCPT TO takes a BARE address, never a display-name form. Operator-supplied
	// addresses (ADMIN_EMAIL, CONTACT_TO) are validated with mail.ParseAddress,
	// which happily accepts `Ops <ops@example.com>` — so without this the config
	// looked valid and then every send to it failed at RCPT, silently, which is the
	// precise failure mode that validation was added to prevent.
	to = envelopeAddress(to)
	// smtp.SendMail validates these to block SMTP command injection; keep that.
	if strings.ContainsAny(to, "\r\n") {
		return errors.New("mailer: recipient contains CR/LF")
	}
	from := envelopeAddress(m.from)
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
	// This is the ONE stage where a 5xx is evidence about the recipient's address
	// (the classic "user unknown"), so it alone yields ErrBadAddress and can put
	// the address on the do-not-email list. Hammering a dead address is what
	// destroys a sending domain's reputation.
	if err := c.Rcpt(to); err != nil {
		return classifyRecipient(err)
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
	// A nil error from w.Close() means the server wrote the terminating "." and
	// returned its 250: it has ACCEPTED the message. Whatever happens in QUIT after
	// that — a relay that drops the connection right after 250, an EOF, the send
	// deadline expiring during QUIT — does not un-send it. Returning that error would
	// have the outbox mark the row failed and retry it, delivering the same message
	// again (up to the retry cap) and finally alerting the operator that a delivered
	// mail was "undeliverable". So the send is a success from here; a QUIT hiccup is
	// logged, not surfaced.
	if err := c.Quit(); err != nil {
		log.Printf("mailer: QUIT failed after the message was accepted (already delivered, not retrying): %v", err)
	}
	return nil
}

// ErrPermanent marks a send that must never be retried: the server refused it
// with a 5xx, so the address, the sender or the message is rejected outright.
// Callers use errors.Is to decide between "back off and try again" and "stop".
var ErrPermanent = errors.New("permanent SMTP failure")

// ErrBadAddress marks the narrower case where the 5xx was the RECIPIENT being
// rejected — the classic "user unknown" at RCPT TO. It wraps ErrPermanent, so
// anything asking "should I retry?" still gets no; it exists for the one caller
// that asks the much stronger question "is this address itself undeliverable?".
//
// The distinction matters because the answer to that question gets written to a
// suppression list that lasts two years and is invisible to the user. A 5xx at
// MAIL FROM is about OUR sender, and a 5xx at DATA is usually about the message
// (size, content, or an unverified sender in an SES sandbox) — neither is
// evidence that the recipient's mailbox is bad. Treating them as such would let
// one misconfiguration walk the entire user base onto the do-not-email list,
// which is precisely the silent, permanent notification failure this app cannot
// afford: the notifications are what stop people being fined.
var ErrBadAddress = fmt.Errorf("%w: recipient rejected", ErrPermanent)

// classify inspects an SMTP reply and wraps permanent (5xx) refusals with
// ErrPermanent. Transient replies (4xx) and connection-level errors pass through
// unchanged so the existing retry/backoff applies. 421 is a 4xx and already
// transient.
func classify(err error) error {
	return classifyAt(err, ErrPermanent)
}

// classifyRecipient is classify for the RCPT stage, where a 5xx is evidence
// about the recipient's address specifically.
func classifyRecipient(err error) error {
	return classifyAt(err, ErrBadAddress)
}

func classifyAt(err error, permanent error) error {
	if err == nil {
		return nil
	}
	var te *textproto.Error
	if errors.As(err, &te) && te.Code >= 500 && te.Code < 600 {
		return fmt.Errorf("%w: %d %s", permanent, te.Code, te.Msg)
	}
	return err
}

// headerValue neutralises CR/LF in a value destined for an email header, so
// user-influenced content (e.g. a permit or vehicle name in the Subject) can't
// inject extra headers or body — SMTP header injection.
func headerValue(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// envelopeAddress extracts the bare address from a possibly-decorated header
// ("Name <a@b>" → "a@b"); SendMail's envelope-from must be an address only.
func envelopeAddress(from string) string {
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
	addr := envelopeAddress(from)
	if i := strings.LastIndex(addr, "@"); i >= 0 && i+1 < len(addr) {
		if d := strings.TrimSpace(addr[i+1:]); d != "" {
			return d
		}
	}
	return "pstonn.invalid"
}
