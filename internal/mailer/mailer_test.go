package mailer

import (
	"bufio"
	"encoding/base64"
	"errors"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
)

func TestNewDisabledWhenUnset(t *testing.T) {
	if m := New(config.SMTPConfig{}); m != nil {
		t.Fatal("mailer should be nil when SMTP is unconfigured")
	}
	// Host without From is still disabled.
	if m := New(config.SMTPConfig{Host: "smtp.example"}); m != nil {
		t.Fatal("mailer should be nil without From")
	}
	m := New(config.SMTPConfig{Host: "smtp.example", Port: 587, From: "a@b"})
	if !m.Enabled() {
		t.Fatal("mailer should be enabled when Host and From are set")
	}
	// A nil *Mailer is a safe no-op.
	var nilM *Mailer
	if nilM.Enabled() {
		t.Fatal("nil mailer must report disabled")
	}
	if err := nilM.SendOpts("a@b", "s", "b", Options{}); err != nil {
		t.Fatalf("nil mailer send should be a no-op: %v", err)
	}
}

func TestHeaderValueStripsCRLF(t *testing.T) {
	// A CR/LF in a header value (e.g. a permit name flowing into Subject) must not
	// be able to inject additional headers or body — SMTP header injection.
	// Each CR and LF becomes a space; the invariant that matters is simply that no
	// CR or LF survives in the output.
	for _, in := range []string{"Nanny", "Nanny\r\nBcc: attacker@x.co", "a\nb", "a\rb", "line1\r\n\r\nInjected body"} {
		got := headerValue(in)
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("headerValue(%q) = %q still contains CR/LF", in, got)
		}
	}
}

// A server that accepts the connection and then goes silent must not wedge the
// caller: keep-warm and the outbox worker send synchronously, so an unbounded
// hang there stalls session renewal for every user.
func TestSendTimesOutOnStalledServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close() // hold open, send nothing
		}
	}()

	old := smtpExchangeTimeout
	smtpExchangeTimeout = 300 * time.Millisecond
	defer func() { smtpExchangeTimeout = old }()

	m := &Mailer{host: "127.0.0.1", addr: ln.Addr().String(), from: "a@b"}
	done := make(chan error, 1)
	go func() { done <- m.Send("to@example.com", "subj", "body") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from the stalled server")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send did not return: no deadline applied to the SMTP exchange")
	}
}

func TestSendRejectsCRLFRecipient(t *testing.T) {
	m := &Mailer{host: "smtp.example", addr: "smtp.example:587", from: "a@b"}
	if err := m.Send("victim@example.com\r\nRCPT TO:<x@y>", "s", "b"); err == nil {
		t.Fatal("expected CR/LF recipient to be rejected before dialing")
	}
}

func TestEnvelopeAddress(t *testing.T) {
	cases := map[string]string{
		"a@b.com":                       "a@b.com",
		"pstonn <no-reply@example.com>": "no-reply@example.com",
		"  spaced@example.com  ":        "spaced@example.com",
	}
	for in, want := range cases {
		if got := envelopeAddress(in); got != want {
			t.Errorf("envelopeAddress(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestClassify locks the retry/stop decision. A 4xx must stay retryable
// (greylisting is a 4xx and is exactly what retry is for), and a 5xx must not be
// retried at all — burning eight attempts on an address the server already
// refused is how a sending domain's reputation gets destroyed.
func TestClassify(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		permanent bool
	}{
		{"nil", nil, false},
		{"greylisted", &textproto.Error{Code: 450, Msg: "try again later"}, false},
		{"shutting down", &textproto.Error{Code: 421, Msg: "service closing"}, false},
		{"user unknown", &textproto.Error{Code: 550, Msg: "user unknown"}, true},
		{"mailbox gone", &textproto.Error{Code: 551, Msg: "no such user"}, true},
		{"connection error", errors.New("dial tcp: refused"), false},
	}
	for _, c := range cases {
		got := errors.Is(classify(c.err), ErrPermanent)
		if got != c.permanent {
			t.Errorf("%s: permanent = %v, want %v", c.name, got, c.permanent)
		}
	}
}

// TestClassifyRecipientVsMessage is the distinction that keeps a misconfiguration
// from blacklisting the whole user base. Both stages stop the retry loop, but
// only a rejected RECIPIENT is evidence that the address itself is undeliverable,
// and only that may reach the two-year suppression list.
func TestClassifyRecipientVsMessage(t *testing.T) {
	refusal := &textproto.Error{Code: 554, Msg: "Message rejected: Email address is not verified"}

	// A 5xx at MAIL FROM or DATA: about our sender or the message, not the mailbox.
	atMessage := classify(refusal)
	if !errors.Is(atMessage, ErrPermanent) {
		t.Fatal("a 5xx must stop the retry loop wherever it happens")
	}
	if errors.Is(atMessage, ErrBadAddress) {
		t.Fatal("a sender/message-level refusal must NOT be read as a bad recipient: " +
			"an SES sandbox or a From change would suppress every address it touched")
	}

	// The same reply at RCPT TO: this one really is about the address.
	atRecipient := classifyRecipient(refusal)
	if !errors.Is(atRecipient, ErrBadAddress) {
		t.Fatal("a 5xx at RCPT must be reported as a bad address")
	}
	if !errors.Is(atRecipient, ErrPermanent) {
		t.Fatal("ErrBadAddress must still satisfy errors.Is(err, ErrPermanent) so the outbox dead-letters it")
	}

	// A transient reply at RCPT stays retryable — a full mailbox may empty.
	if errors.Is(classifyRecipient(&textproto.Error{Code: 452, Msg: "mailbox full"}), ErrPermanent) {
		t.Fatal("a 4xx at RCPT must remain retryable")
	}
}

// TestSendHeaders asserts the envelope obligations that make transactional mail
// deliverable and lawful. None of these had a test, which is how a whole class of
// enqueued mail shipped with no provenance footer.
func TestSendHeaders(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var received strings.Builder
		br := bufio.NewReader(conn)
		write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		write("220 test ESMTP")
		inData := false
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			if inData {
				if strings.TrimRight(line, "\r\n") == "." {
					write("250 OK")
					got <- received.String()
					inData = false // keep serving: deliver still sends QUIT
					continue
				}
				received.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				write("250-test")
				write("250 SIZE 10240000")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				write("250 OK")
			case strings.HasPrefix(cmd, "DATA"):
				write("354 send it")
				inData = true
			case strings.HasPrefix(cmd, "QUIT"):
				write("221 bye")
				return
			default:
				write("250 OK")
			}
		}
	}()

	m := &Mailer{host: "127.0.0.1", addr: ln.Addr().String(), from: "p.stonn <no-reply@stonn.org>"}
	err = m.SendOpts("guest@example.com", "Permit updated", "Your plate is on the permit.", Options{
		UnsubscribeURL: "https://p.stonn.org/u/guest@example.com/abc123",
		Provenance:     "You received this at guest@example.com because someone shared their permit with you.",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case msg := <-got:
		for _, want := range []string{
			"From: ",
			"To: guest@example.com",
			"Date: ",
			"Message-ID: ",
			"Auto-Submitted: auto-generated",
			"List-Unsubscribe: <https://p.stonn.org/u/guest@example.com/abc123>",
			"List-Unsubscribe-Post: List-Unsubscribe=One-Click",
			"Subject: Permit updated",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("missing header %q", want)
			}
		}
		// The provenance and unsubscribe footer must reach the body, not just the
		// headers: it is the human-readable half of the same obligation. The body is
		// base64 in both MIME parts, so decode to check.
		if !strings.Contains(decodeAnyBase64(msg), "because someone shared their permit with you") {
			t.Error("provenance footer missing from the message body")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no message received")
	}
}

// decodeAnyBase64 concatenates the decoding of every base64-looking run in s, so
// the test can assert on MIME-encoded body content without a full MIME parser.
func decodeAnyBase64(s string) string {
	var out strings.Builder
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 8 {
			continue
		}
		if b, err := base64.StdEncoding.DecodeString(line); err == nil {
			out.Write(b)
		}
	}
	return out.String()
}
