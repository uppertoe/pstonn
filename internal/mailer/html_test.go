package mailer

import "strings"

import "testing"

func TestHTMLDocument(t *testing.T) {
	body := strings.Join([]string{
		"Hi,",
		"",
		"Your <permit> was updated & is now active.",
		"",
		"Confirm and keep it running (one click):",
		"https://p.stonn.org/council/confirm?token=abc",
		"",
		"-- p.stonn",
	}, "\n")
	got := htmlDocument("Permit updated", body, "Not affiliated with the City of Stonnington.")

	checks := []string{
		`p<span style="color:#0d9488;">.</span>stonn`,          // wordmark with teal dot
		`Your &lt;permit&gt; was updated &amp; is now active.`, // HTML-escaped content
		`href="https://p.stonn.org/council/confirm?token=abc"`, // the URL is linked
		`Confirm and keep it running (one click)</a>`,          // label came from the "label:" line
		`Not affiliated with the City of Stonnington`,          // footer disclaimer
	}
	for _, c := range checks {
		if !strings.Contains(got, c) {
			t.Errorf("rendered HTML missing %q\n---\n%s", c, got)
		}
	}
	// The signature line is dropped (the footer replaces it).
	if strings.Contains(got, "-- p.stonn") {
		t.Error("signature '-- p.stonn' should be stripped from the HTML body")
	}
	// A whole-line URL renders as a button, not a bare paragraph link.
	if !strings.Contains(got, "background:#0d9488;\"><a href=\"https://p.stonn.org/council/confirm") {
		t.Errorf("standalone URL should render as a teal button:\n%s", got)
	}
}
