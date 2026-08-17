package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/uppertoe/pstonn/internal/identity"
)

// SEO lives here because the public pages are how a Stonnington resident actually
// FINDS this tool: a search for "Stonnington visitor parking permit" has to land
// on something. Per-page title + description, a canonical URL, Open Graph tags for
// shared links, JSON-LD, a sitemap and a robots.txt — all keyed off the page State
// so the app/guest/token pages stay noindex.

// seoFor returns the <title>, meta description, and canonical PATH for a page
// State. An empty path marks the page NON-indexable (app, guest, confirm, token
// pages): the head emits noindex and no canonical/OG for those.
func seoFor(state string) (title, desc, canonPath string) {
	switch state {
	case "landing":
		return "Stonnington visitor parking permits, on a schedule — p.stonn",
			"Free tool to schedule which car is on your City of Stonnington visitor parking permit: a weekly roster, a permanent link for family, or a QR code for tradies. Open source, unofficial.",
			"/"
	case "how":
		return "How p.stonn manages your Stonnington visitor permit",
			"Connect your Stonnington ePermits login once, then p.stonn puts the right car on your visitor permit to your weekly schedule — plus one-off changes, guest links and printed QR codes.",
			"/how"
	case "security":
		return "Security & data — p.stonn",
			"What p.stonn encrypts, how long it keeps anything, what a breach could and couldn't reach, and how to delete it all. A free, unofficial City of Stonnington parking tool.",
			"/security"
	case "contact":
		return "Contact — p.stonn",
			"Questions about p.stonn, the free scheduler for City of Stonnington visitor parking permits? Get in touch.",
			"/contact"
	case "faq":
		return "FAQ — p.stonn visitor parking permit scheduler",
			"Answers about scheduling your City of Stonnington visitor parking permit with p.stonn: recurring visitor parking, sharing with family, cost, safety, and whether it is affiliated with the council.",
			"/faq"
	default:
		// App, guest, confirm and token pages: a stable generic title, never indexed.
		return "p.stonn Visitor Permit Scheduler", "", ""
	}
}

// faqItem is one question/answer. Answers are PLAIN TEXT so the same slice feeds
// both the rendered page and the FAQPage JSON-LD without markup leaking into the
// structured data (Google rejects HTML it doesn't expect there).
type faqItem struct{ Q, A string }

var faqItems = []faqItem{
	{
		"How do I change the car on my Stonnington visitor parking permit?",
		"Connect your ePermits login to p.stonn once, then set a weekly schedule of which car should be on the permit on which days. p.stonn changes the vehicle on your permit automatically as the schedule rolls over, and you can make a one-off change at any time.",
	},
	{
		"Can I set up recurring visitor parking for a carer or family member?",
		"Yes. Set a weekly roster — say a carer's car every Tuesday and Thursday — or share a permanent guest link so a trusted person can put their own car on the permit when they arrive, with no account needed on their end.",
	},
	{
		"Is p.stonn affiliated with the City of Stonnington?",
		"No. p.stonn is a free, independent, open-source tool. It is not made by, endorsed by, or affiliated with the council.",
	},
	{
		"Is it safe to give p.stonn my ePermits login?",
		"Your login is encrypted, used only to manage your own permit, and you can disconnect or delete everything at any time. It is a council parking account, not a bank login. If you would rather not share it at all, p.stonn is open source and you can run your own copy — the Security & data page has the full detail.",
	},
	{
		"What does p.stonn cost?",
		"Nothing. It is free.",
	},
	{
		"Which council does p.stonn work with?",
		"The City of Stonnington's visitor parking permits (the ePermits system). It does not support other councils yet.",
	},
}

// jsonLDFor returns the structured-data script body for a page State, already
// JSON-encoded (json.Marshal escapes < > & so it is safe to drop into a
// <script type="application/ld+json"> without html/template re-escaping it). Empty
// for pages that carry no structured data.
func jsonLDFor(state, baseURL string) template.JS {
	var v any
	switch state {
	case "landing":
		title, desc, path := seoFor("landing")
		v = map[string]any{
			"@context":            "https://schema.org",
			"@type":               "WebApplication",
			"name":                "p.stonn",
			"alternateName":       title,
			"description":         desc,
			"url":                 baseURL + path,
			"applicationCategory": "UtilitiesApplication",
			"operatingSystem":     "Web",
			"isAccessibleForFree": true,
			"offers":              map[string]any{"@type": "Offer", "price": "0", "priceCurrency": "AUD"},
		}
	case "faq":
		qs := make([]map[string]any, 0, len(faqItems))
		for _, f := range faqItems {
			qs = append(qs, map[string]any{
				"@type":          "Question",
				"name":           f.Q,
				"acceptedAnswer": map[string]any{"@type": "Answer", "text": f.A},
			})
		}
		v = map[string]any{"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": qs}
	default:
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "" // never break a page over structured data
	}
	return template.JS(b)
}

// faq is the PUBLIC FAQ page: resident-phrased questions, kept in step with the
// FAQPage structured data so an answer can surface directly in search results.
func (s *Server) faq(w http.ResponseWriter, r *http.Request) {
	_, signedIn := identity.FromContext(r.Context())
	s.render(w, dashboardData{State: "faq", SignedIn: signedIn, Contact: s.cfg.ContactEnabled(), Loc: s.cfg.DisplayLocation, FAQ: faqItems})
}

// robotsTxt lets crawlers index the public pages while keeping them off the app,
// the admin view, and every token-bearing link (guest passes, unsubscribe,
// confirm) — a crawled token is a leaked token. Points at the sitemap.
func (s *Server) robotsTxt(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString("User-agent: *\n")
	for _, p := range []string{
		"/schedule", "/account", "/vehicles", "/permits", "/guests",
		"/settings", "/notifications", "/admin", "/auth/", "/council/",
		"/g/", "/u/", "/status",
	} {
		fmt.Fprintf(&b, "Disallow: %s\n", p)
	}
	if s.cfg.PublicBaseURL != "" {
		fmt.Fprintf(&b, "\nSitemap: %s/sitemap.xml\n", s.cfg.PublicBaseURL)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(b.String()))
}

// sitemapXML lists the indexable public pages so a search engine discovers them
// without guessing. Only the four content pages plus the FAQ — nothing behind auth.
func (s *Server) sitemapXML(w http.ResponseWriter, r *http.Request) {
	base := s.cfg.PublicBaseURL
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, p := range []string{"/", "/how", "/security", "/contact", "/faq"} {
		fmt.Fprintf(&b, "  <url><loc>%s%s</loc></url>\n", base, p)
	}
	b.WriteString("</urlset>\n")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(b.String()))
}
