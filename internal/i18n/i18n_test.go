package i18n

import (
	"strings"
	"testing"
)

type councilStub struct {
	Name, Short string
	Terms       map[string]string
}

func TestCatalogsLoadAndRender(t *testing.T) {
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if b.For("xx-YY").Locale != DefaultLocale {
		t.Fatal("unknown locale must fall back to the default")
	}
	c := b.For(DefaultLocale)
	data := map[string]any{"Council": councilStub{Name: "City of Stonnington", Short: "Stonnington", Terms: c.Terms(nil)}}
	got, err := c.HTML("onboarding.intro", data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "City of Stonnington ePermits details") {
		t.Fatalf("rendered %q", got)
	}
	// Text rendering of the same key, for mail.
	if s, err := c.Text("onboarding.intro", data); err != nil || !strings.Contains(s, "ePermits") {
		t.Fatalf("text: %q %v", s, err)
	}
	// Interpolated data is escaped in HTML context, message markup is not.
	hostile := map[string]any{"Council": councilStub{Name: "<b>x</b>", Terms: c.Terms(nil)}}
	if out, _ := c.HTML("guest.credit", hostile); strings.Contains(string(out), "<b>x</b>") || !strings.Contains(string(out), "<a href=") {
		t.Fatalf("escaping wrong: %q", out)
	}
	if _, err := c.HTML("no.such.key", data); err == nil {
		t.Fatal("missing key must error, not render empty")
	}
}

func TestTermsOverride(t *testing.T) {
	c := MustLoad().For(DefaultLocale)
	terms := c.Terms(map[string]string{"portal": "ParkPortal", "permit": "  "})
	if terms["portal"] != "ParkPortal" {
		t.Fatalf("override lost: %v", terms)
	}
	if terms["permit"] != "visitor permit" {
		t.Fatalf("blank override must keep the default: %v", terms)
	}
	// Messages composed from terms follow the override.
	data := map[string]any{"Council": councilStub{Name: "Othertown", Short: "Othertown", Terms: terms}}
	if out, _ := c.HTML("onboarding.email_pinned", data); !strings.Contains(string(out), "ParkPortal account") {
		t.Fatalf("terminology not applied: %q", out)
	}
}

// A message may include another with T; the included key must exist too.
func TestNestedInclude(t *testing.T) {
	c := MustLoad().For(DefaultLocale)
	data := map[string]any{"Council": map[string]any{"Name": "N", "Links": map[string]string{"ApplyVisitor": "https://a", "FAQ": "https://f"}, "Terms": c.Terms(nil)}}
	out, err := c.HTML("public.faq_more", data)
	if err != nil || !strings.Contains(string(out), `href="https://a"`) {
		t.Fatalf("nested include: %q %v", out, err)
	}
}
