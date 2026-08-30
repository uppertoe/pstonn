package redact

import "testing"

func TestEmail(t *testing.T) {
	cases := map[string]string{
		"primary@example.com": "p***@example.com",
		"UPPER@Example.COM":   "U***@example.com", // domain lower-cased, mailbox initial kept
		"  spaced@x.io  ":     "s***@x.io",
		"":                    "(none)",
		"not-an-address":      "***",
		"@nodomain":           "***", // no local part
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

// A server's rejection echoes the recipient; InText must scrub every spelling of
// it, and only it.
func TestInText(t *testing.T) {
	const addr = "Guest.One@Example.com"
	in := "permanent SMTP failure: recipient rejected: 550 5.1.1 <guest.one@example.com>: user unknown (GUEST.ONE@EXAMPLE.COM)"
	got := InText(in, addr, "")
	want := "permanent SMTP failure: recipient rejected: 550 5.1.1 <G***@example.com>: user unknown (G***@example.com)"
	if got != want {
		t.Fatalf("InText =\n %q\nwant\n %q", got, want)
	}
	// Not the address: untouched.
	if got := InText("dial tcp: i/o timeout", addr); got != "dial tcp: i/o timeout" {
		t.Fatalf("InText altered text it should not have: %q", got)
	}
	// An empty address must not match everywhere.
	if got := InText("abc", ""); got != "abc" {
		t.Fatalf("InText with an empty address = %q", got)
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
