package i18n

import (
	htmltemplate "html/template"
	"strings"
	"testing"
)

func render(s Slot) string { return string(s(htmltemplate.HTML("x"))) }

func TestLinkOptionsAreTypedAndEscaped(t *testing.T) {
	got := render(Link(`https://example.org/a?b=1&c="q"`, NewTab(), NoBoost()))
	want := `<a href="https://example.org/a?b=1&amp;c=&#34;q&#34;" target="_blank" rel="noopener noreferrer" hx-boost="false">x</a>`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if got := render(Link("/schedule")); got != `<a href="/schedule">x</a>` {
		t.Fatalf("bare link: %s", got)
	}
}

// The href is the only caller-supplied value that reaches the tag, and it can
// come from configuration; a script-bearing scheme must never render.
func TestLinkRefusesUnsafeSchemes(t *testing.T) {
	for _, bad := range []string{
		"javascript:alert(1)", "JavaScript:alert(1)", " javascript:alert(1)",
		"data:text/html,x", "vbscript:x", "//evil.example.net/x", "",
	} {
		if got := render(Link(bad, NewTab())); !strings.Contains(got, `href="#"`) {
			t.Errorf("Link(%q) rendered %s; want href=\"#\"", bad, got)
		}
	}
	for _, ok := range []string{"https://a.example/x", "http://a.example/x", "/x", "#top", "?q=1", "guide/one"} {
		if got := render(Link(ok)); strings.Contains(got, `href="#"`) && ok != "#top" {
			t.Errorf("Link(%q) was refused: %s", ok, got)
		}
	}
}
