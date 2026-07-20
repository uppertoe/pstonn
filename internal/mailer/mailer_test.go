package mailer

import (
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
