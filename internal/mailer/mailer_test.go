package mailer

import (
	"net"
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
	if err := nilM.SendRenewalReminder("a@b", time.Time{}, "url"); err != nil {
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

func TestSenderAddress(t *testing.T) {
	cases := map[string]string{
		"a@b.com":                       "a@b.com",
		"pstonn <no-reply@example.com>": "no-reply@example.com",
		"  spaced@example.com  ":        "spaced@example.com",
	}
	for in, want := range cases {
		if got := senderAddress(in); got != want {
			t.Errorf("senderAddress(%q) = %q, want %q", in, got, want)
		}
	}
}
