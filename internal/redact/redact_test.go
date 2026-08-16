package redact

import "testing"

func TestEmail(t *testing.T) {
	cases := map[string]string{
		"lily@example.com":  "l***@example.com",
		"UPPER@Example.COM": "U***@example.com", // domain lower-cased, mailbox initial kept
		"  spaced@x.io  ":   "s***@x.io",
		"":                  "(none)",
		"not-an-address":    "***",
		"@nodomain":         "***", // no local part
	}
	for in, want := range cases {
		if got := Email(in); got != want {
			t.Errorf("Email(%q) = %q, want %q", in, got, want)
		}
	}
	// The whole address must never survive into the output.
	if got := Email("secret.person@council.vic.gov.au"); got == "secret.person@council.vic.gov.au" {
		t.Fatal("Email returned the address unredacted")
	}
}

func TestEmails(t *testing.T) {
	if got := Emails(nil); got != "(none)" {
		t.Errorf("Emails(nil) = %q, want (none)", got)
	}
	if got := Emails([]string{"a@x.io", "b@y.io"}); got != "a***@x.io, b***@y.io" {
		t.Errorf("Emails = %q", got)
	}
}
