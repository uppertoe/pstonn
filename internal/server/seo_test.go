package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/config"
)

func TestSeoForIndexability(t *testing.T) {
	// The public content pages must be fully indexable.
	for _, st := range []string{"landing", "how", "security", "contact", "faq"} {
		title, desc, path := seoFor(st)
		if title == "" || desc == "" || path == "" {
			t.Errorf("seoFor(%q): want fully indexable, got title=%q desc=%q path=%q", st, title, desc, path)
		}
	}
	// Everything else (the app, guest menus, token/confirm pages) must be
	// non-indexable — an empty canonical path is what the head turns into noindex.
	for _, st := range []string{"app", "guest", "guest-wait", "confirm", "picker", ""} {
		if _, _, path := seoFor(st); path != "" {
			t.Errorf("seoFor(%q): want non-indexable (empty path), got %q", st, path)
		}
	}
}

func TestJSONLD(t *testing.T) {
	const base = "https://p.stonn.org"
	if ld := string(jsonLDFor("landing", base)); !strings.Contains(ld, `"@type":"WebApplication"`) ||
		!strings.Contains(ld, `"url":"https://p.stonn.org/"`) || !strings.Contains(ld, `"isAccessibleForFree":true`) {
		t.Errorf("landing JSON-LD wrong: %s", ld)
	}
	ld := string(jsonLDFor("faq", base))
	if !strings.Contains(ld, `"@type":"FAQPage"`) {
		t.Fatalf("faq JSON-LD not a FAQPage: %s", ld)
	}
	// Every FAQ item must appear as a Question in the structured data, so a search
	// result can never show an answer that isn't on the page.
	if got := strings.Count(ld, `"@type":"Question"`); got != len(faqItems) {
		t.Errorf("faq JSON-LD has %d Questions, want %d", got, len(faqItems))
	}
	if jsonLDFor("app", base) != "" {
		t.Error("app pages must carry no JSON-LD")
	}
}

func TestRobotsAndSitemap(t *testing.T) {
	s := &Server{cfg: &config.Config{PublicBaseURL: "https://p.stonn.org"}}

	rr := httptest.NewRecorder()
	s.robotsTxt(rr, httptest.NewRequest("GET", "/robots.txt", nil))
	robots := rr.Body.String()
	for _, must := range []string{"Disallow: /g/", "Disallow: /admin", "Disallow: /status", "Sitemap: https://p.stonn.org/sitemap.xml"} {
		if !strings.Contains(robots, must) {
			t.Errorf("robots.txt missing %q:\n%s", must, robots)
		}
	}
	// Public content pages must NOT be blocked.
	for _, pub := range []string{"Disallow: /how", "Disallow: /security", "Disallow: /faq", "Disallow: /contact"} {
		if strings.Contains(robots, pub) {
			t.Errorf("robots.txt wrongly blocks a public page: %q", pub)
		}
	}

	rr = httptest.NewRecorder()
	s.sitemapXML(rr, httptest.NewRequest("GET", "/sitemap.xml", nil))
	sitemap := rr.Body.String()
	for _, u := range []string{"https://p.stonn.org/", "https://p.stonn.org/how", "https://p.stonn.org/security", "https://p.stonn.org/contact", "https://p.stonn.org/faq"} {
		if !strings.Contains(sitemap, "<loc>"+u+"</loc>") {
			t.Errorf("sitemap missing <loc>%s</loc>:\n%s", u, sitemap)
		}
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/xml") {
		t.Errorf("sitemap Content-Type = %q, want application/xml", ct)
	}
}
