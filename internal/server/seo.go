package server

import (
	"encoding/json"
	"fmt"
	"github.com/uppertoe/pstonn/internal/i18n"
	"html/template"
	"io/fs"
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
func seoFor(state string, c tenantView) (title, desc, canonPath string) {
	switch state {
	case "landing":
		return trText(c, "seo.landing_title"), trText(c, "seo.landing_desc"), "/"
	case "how":
		return trText(c, "seo.how_title"), trText(c, "seo.how_desc"), "/how"
	case "security":
		return "Security & data — p.stonn", trText(c, "seo.security_desc"), "/security"
	case "contact":
		return "Contact — p.stonn", trText(c, "seo.contact_desc"), "/contact"
	case "faq":
		return "FAQ — p.stonn visitor parking permit scheduler", trText(c, "seo.faq_desc"), "/faq"
	default:
		// App, guest, confirm and token pages: a stable generic title, never indexed.
		return "p.stonn Visitor Permit Scheduler", "", ""
	}
}

// faqItem is one question/answer. Answers are PLAIN TEXT so the same slice feeds
// both the rendered page and the FAQPage JSON-LD without markup leaking into the
// structured data (Google rejects HTML it doesn't expect there).
type faqItem struct{ Q, A string }

// faqFor is the FAQ for a tenant.
func faqFor(c tenantView) []faqItem {
	return []faqItem{
		{
			"Can I set up recurring visitor parking for a carer or family member?",
			"Yes. Set a weekly roster — say a carer's car every Tuesday and Thursday — or share a permanent guest link so a trusted person can put their own car on the permit when they arrive, with no account needed on their end.",
		},
		{
			trText(c, "faq.affiliated_q"),
			"No. p.stonn is a free, independent, open-source tool. It is not made by, endorsed by, or affiliated with the council.",
		},
		{
			trText(c, "faq.safe_q"),
			"Your login is encrypted, used only to manage your own permit, and you can disconnect or delete everything at any time. It is a council parking account, not a bank login. If you would rather not share it at all, p.stonn is open source and you can run your own copy — the Security & data page has the full detail.",
		},
		{
			"My partner set up the permit — can I manage the schedule too?",
			"Yes. Whoever set it up can invite up to two other people from Settings → Shared access. You sign in with your own email and manage the same schedule — no council password changes hands.",
		},
		{
			"What does p.stonn cost?",
			"Nothing. It is free.",
		},
		{
			"Which council does p.stonn work with?",
			trText(c, "faq.which_council_a"),
		},
	}
}

// jsonLDFor returns the structured-data script body for a page State, already
// JSON-encoded (json.Marshal escapes < > & so it is safe to drop into a
// <script type="application/ld+json"> without html/template re-escaping it). Empty
// for pages that carry no structured data.
func jsonLDFor(state, baseURL string, c tenantView) template.JS {
	var v any
	switch state {
	case "landing":
		title, desc, path := seoFor("landing", c)
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
		faq := faqFor(c)
		qs := make([]map[string]any, 0, len(faq))
		for _, f := range faq {
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
	s.render(w, dashboardData{State: "faq", SignedIn: signedIn, Contact: s.cfg.ContactEnabled(), Loc: s.cfg.DisplayLocation, FAQ: faqFor(s.tenantViewFor(r.Context(), ""))})
}

// robotsTxt lets crawlers index the public pages while keeping them off the app,
// the admin view, and every token-bearing link (guest passes, unsubscribe,
// confirm) — a crawled token is a leaked token. Points at the sitemap.
func (s *Server) robotsTxt(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString("User-agent: *\n")
	for _, p := range []string{
		"/schedule", "/account", "/vehicles", "/permits", "/guests",
		"/settings", "/notifications", "/admin", "/auth/", "/tenant/",
		"/g/", "/u/", "/r/", "/status",
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

// faviconICO answers the /favicon.ico that browsers and crawlers request at the
// root regardless of the <link> tags. The inline SVG icon covers modern tabs; this
// serves the 192px PNG so the bare .ico fetch is a 200, not a 404, everywhere else.
func (s *Server) faviconICO(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(staticSub, "icon-192.png")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=604800")
	_, _ = w.Write(b)
}

// siteManifest is the site-wide web app manifest (the guest links have their own,
// scoped to /g/). It names the app and points at the 192/512 icons so Android's
// "Add to home screen" and general PWA metadata are complete.
func (s *Server) siteManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	name, _ := json.Marshal(trText(s.tenantViewFor(r.Context(), ""), "seo.manifest_name"))
	fmt.Fprint(w, `{
  "id": "/",
  "name": `+string(name)+`,
  "short_name": "p.stonn",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "theme_color": "#0d9488",
  "background_color": "#eceff5",
  "icons": [
    {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
    {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}
  ]
}`)
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
	for _, g := range guidesFor(s.tenantViewFor(r.Context(), "")) {
		fmt.Fprintf(&b, "  <url><loc>%s/guide/%s</loc></url>\n", base, g.Slug)
	}
	b.WriteString("</urlset>\n")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(b.String()))
}

// guidePage is one question-shaped public page: the title is the question a
// resident types into a search box; the body answers it properly — how it is
// done at the tenant (real steps, real links), then how p.stonn does it with
// the matching animated demo — and the tool comes last. Paras (plain text) are
// the short answer and feed the structured data; Steps may carry links.
type guidePage struct {
	Slug          string // /guide/<slug>
	Title         string // <title> and og:title
	Desc          string // meta description
	H1            string // the question, as the page heading
	Paras         []string
	TenantHeading string
	Steps         []template.HTML
	TenantNote    template.HTML
	Pstonn        string
	Demo          string // "roster" | "oneoff" | "guest" — the How page demo to embed
}

// The tenant's own instructions (its visitor-permits page, read 2026-08-29):
// allocate via the ePermit platform — "Update Vehicle" in the Current Permit
// list, registration plus state — or by phone; a physical permit is available on
// application under "exceptional circumstances" (disability, carer arrangements,
// limits with online connection and capability).
func tenantSignInSteps(c tenantView) []template.HTML {
	return []template.HTML{
		tr(c, "guide.signin_step", nil, i18n.Slots{
			"portal":   i18n.Link(c.Links.Portal, i18n.NewTab()),
			"register": i18n.Link(c.Links.Register, i18n.NewTab()),
			"reset":    i18n.Link(c.Links.ResetPassword, i18n.NewTab()),
		}),
		template.HTML(`In your Current Permit list, choose <strong>Update Vehicle</strong> on the visitor permit.`),
		template.HTML(`Enter the new registration and the state it&rsquo;s registered in, and save.`),
	}
}

// guidesFor is the guide set for a tenant: the same questions, with the
// tenant's name, links and vocabulary in the answers.
func guidesFor(c tenantView) []guidePage {
	steps := tenantSignInSteps(c)
	return []guidePage{
		{
			Slug:          "change-car-on-visitor-permit",
			Title:         trText(c, "guide.change_title"),
			Desc:          trText(c, "guide.change_desc"),
			H1:            trText(c, "guide.change_h1"),
			Paras:         []string{trText(c, "guide.change_para")},
			TenantHeading: "At the council",
			Steps: append(append([]template.HTML{}, steps...),
				template.HTML(`Repeat for each new visitor, before they park.`)),
			TenantNote: tr(c, "guide.change_note", nil, nil),
			Pstonn:     "Set it once. A weekly roster puts the right car on for each day, a one-off booking covers everyone else, and a link lets a regular visitor put their own car on when they arrive.",
			Demo:       "roster",
		},
		{
			Slug:  "visitor-parking-cleaner-nanny-carer",
			Title: trText(c, "guide.carer_title"),
			Desc:  trText(c, "guide.carer_desc"),
			H1:    trText(c, "guide.carer_h1"),
			Paras: []string{
				"A visitor permit covers one car at a time, so for someone who comes every week the vehicle has to be updated before each visit. If it isn't, they will not be covered by the permit.",
			},
			TenantHeading: "At the council, each visit",
			Steps:         steps,
			TenantNote:    tr(c, "guide.carer_note", nil, i18n.Slots{"apply": i18n.Link(c.Links.ApplyVisitor, i18n.NewTab())}),
			Pstonn:        "Put their day on the weekly roster and the permit switches to their car that morning. Or send them a link, and they put their car on themselves when they pull up — no account, nothing for them to set up.",
			Demo:          "guest",
		},
		{
			Slug:  "paper-visitor-permits",
			Title: trText(c, "guide.paper_title"),
			Desc:  trText(c, "guide.paper_desc"),
			H1:    trText(c, "guide.paper_h1"),
			Paras: []string{
				"Not usually. Permits are digital by default: there's nothing to display, and parking officers check the plate against your permit. Physical permits you already hold stay valid until they expire, and the council will issue one on application in exceptional circumstances — disability, carer arrangements, or limited online access.",
			},
			TenantHeading: "To see which plate is on your permit now",
			Steps: []template.HTML{
				steps[0],
				template.HTML(`Find the visitor permit in your Current Permit list &mdash; the vehicle shown is the one that&rsquo;s covered right now.`),
				template.HTML(`If it&rsquo;s the wrong car, choose <strong>Update Vehicle</strong> and enter the visitor&rsquo;s registration before they park.`),
			},
			TenantNote: tr(c, "guide.paper_note", nil, i18n.Slots{"apply": i18n.Link(c.Links.ApplyVisitor, i18n.NewTab())}),
			Pstonn:     "A weekly roster for regulars, one-off bookings for everyone else, a link or QR your visitors use themselves — and a notification each time the plate changes, so you know who's covered.",
			Demo:       "oneoff",
		},
	}
}

func guideBySlug(slug string, c tenantView) *guidePage {
	guides := guidesFor(c)
	for i := range guides {
		if guides[i].Slug == slug {
			return &guides[i]
		}
	}
	return nil
}

// guide serves one public question page.
func (s *Server) guide(w http.ResponseWriter, r *http.Request) {
	g := guideBySlug(r.PathValue("slug"), s.tenantViewFor(r.Context(), ""))
	if g == nil {
		http.NotFound(w, r)
		return
	}
	_, signedIn := identity.FromContext(r.Context())
	s.render(w, dashboardData{State: "guide", Guide: g, SignedIn: signedIn, Contact: s.cfg.ContactEnabled(), Loc: s.cfg.DisplayLocation})
}

// guideJSONLD is a one-question FAQPage: the page IS the answer to its title.
func guideJSONLD(g *guidePage) template.JS {
	v := map[string]any{"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": []map[string]any{{
		"@type":          "Question",
		"name":           g.H1,
		"acceptedAnswer": map[string]any{"@type": "Answer", "text": strings.Join(g.Paras, " ")},
	}}}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return template.JS(b)
}
