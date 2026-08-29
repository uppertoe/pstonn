package server

import (
	"encoding/json"
	"fmt"
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
func seoFor(state string) (title, desc, canonPath string) {
	switch state {
	case "landing":
		return "Stonnington visitor parking permits, on a schedule — p.stonn",
			"Free tool to schedule the car on your City of Stonnington visitor parking permit — a weekly roster, a family link, or a QR code for tradies. Unofficial.",
			"/"
	case "how":
		return "How p.stonn manages your Stonnington visitor permit",
			"Connect your Stonnington ePermits login once; p.stonn sets your visitor permit to your weekly car schedule, plus one-off changes and guest QR links.",
			"/how"
	case "security":
		return "Security & data — p.stonn",
			"What p.stonn encrypts, how long it keeps your data, what a breach could reach, and how to delete everything. A free, unofficial Stonnington parking tool.",
			"/security"
	case "contact":
		return "Contact — p.stonn",
			"Questions about p.stonn, the free scheduler for City of Stonnington visitor parking permits? Get in touch.",
			"/contact"
	case "faq":
		return "FAQ — p.stonn visitor parking permit scheduler",
			"Answers about scheduling your City of Stonnington visitor parking permit with p.stonn — recurring visitor parking, sharing with family, cost, and safety.",
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
		"My partner set up the permit — can I manage the schedule too?",
		"Yes. Whoever set it up can invite up to two other people from Settings → Shared access. You sign in with your own email and manage the same schedule — no council password changes hands.",
	},
	{
		"What does p.stonn cost?",
		"Nothing. It is free.",
	},
	{
		"Which council does p.stonn work with?",
		"The City of Stonnington's visitor parking permits (the ePermits system) — covering Prahran, Windsor, South Yarra, Toorak, Armadale, Malvern, Malvern East and Kooyong. It does not support other councils yet.",
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
	fmt.Fprint(w, `{
  "id": "/",
  "name": "p.stonn — Stonnington visitor parking permits",
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
	for _, g := range guides {
		fmt.Fprintf(&b, "  <url><loc>%s/guide/%s</loc></url>\n", base, g.Slug)
	}
	b.WriteString("</urlset>\n")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(b.String()))
}

// guidePage is one question-shaped public page: the title is the question a
// resident types into a search box; the body answers it properly — how it is
// done at the council (real steps, real links), then how p.stonn does it with
// the matching animated demo — and the tool comes last. Paras (plain text) are
// the short answer and feed the structured data; Steps may carry links.
type guidePage struct {
	Slug           string // /guide/<slug>
	Title          string // <title> and og:title
	Desc           string // meta description
	H1             string // the question, as the page heading
	Paras          []string
	CouncilHeading string
	Steps          []template.HTML
	CouncilNote    template.HTML
	Pstonn         string
	Demo           string // "roster" | "oneoff" | "guest" — the How page demo to embed
}

const (
	councilPortal   = "https://parkingpermits.stonnington.vic.gov.au/"
	councilRegister = "https://parkingpermits.stonnington.vic.gov.au/idm/account/Register"
	councilReset    = "https://parkingpermits.stonnington.vic.gov.au/idm/account/ForgotPassword"
	councilVisitor  = "https://www.stonnington.vic.gov.au/Services/Parking/Parking-permits/Visitor-parking-permits"
)

// The council's own instructions (its visitor-permits page, read 2026-08-29):
// allocate via the ePermit platform — "Update Vehicle" in the Current Permit
// list, registration plus state — or by phone on 03 8290 1333; a physical
// permit is available on application under "exceptional circumstances"
// (disability, carer arrangements, limits with online connection and capability).
var councilSignInSteps = []template.HTML{
	template.HTML(`Sign in at <a href="` + councilPortal + `" target="_blank" rel="noopener">parkingpermits.stonnington.vic.gov.au</a> &mdash; <a href="` + councilRegister + `" target="_blank" rel="noopener">register</a> first if you haven&rsquo;t, or <a href="` + councilReset + `" target="_blank" rel="noopener">reset your password</a> if you&rsquo;ve never used it.`),
	template.HTML(`In your Current Permit list, choose <strong>Update Vehicle</strong> on the visitor permit.`),
	template.HTML(`Enter the new registration and the state it&rsquo;s registered in, and save.`),
}

var guides = []guidePage{
	{
		Slug:  "change-car-on-visitor-permit",
		Title: "How do I change the car on my Stonnington visitor permit? — p.stonn",
		Desc:  "Changing the vehicle on a City of Stonnington visitor parking permit: the steps on the council's ePermits site, and how to stop doing it by hand.",
		H1:    "How do I change the car on my Stonnington visitor permit?",
		Paras: []string{
			"On the council's ePermits site: sign in, choose Update Vehicle on the permit, enter the new plate, save. It has to be done before each visitor parks.",
		},
		CouncilHeading: "At the council",
		Steps: append(append([]template.HTML{}, councilSignInSteps...),
			template.HTML(`Repeat for each new visitor, before they park.`)),
		CouncilNote: template.HTML(`You can also ring the council on 03 8290 1333 to have the vehicle changed.`),
		Pstonn:      "Set it once. A weekly roster puts the right car on for each day, a one-off booking covers everyone else, and a link lets a regular visitor put their own car on when they arrive.",
		Demo:        "roster",
	},
	{
		Slug:  "visitor-parking-cleaner-nanny-carer",
		Title: "Visitor parking for a cleaner, nanny or carer in Stonnington — p.stonn",
		Desc:  "A City of Stonnington visitor permit covers one car at a time. How to handle a cleaner, nanny or carer who comes every week without changing the plate by hand.",
		H1:    "Visitor parking for a cleaner, nanny or carer in Stonnington",
		Paras: []string{
			"A visitor permit covers one car at a time, so for someone who comes every week the vehicle has to be updated before each visit. If it isn't, they will not be covered by the permit.",
		},
		CouncilHeading: "At the council, each visit",
		Steps:          councilSignInSteps,
		CouncilNote:    template.HTML(`Carer arrangements can also qualify for a physical permit under the council&rsquo;s <a href="` + councilVisitor + `" target="_blank" rel="noopener">exceptional circumstances</a> provision &mdash; worth asking about if the online system doesn&rsquo;t suit your household.`),
		Pstonn:         "Put their day on the weekly roster and the permit switches to their car that morning. Or send them a link, and they put their car on themselves when they pull up — no account, nothing for them to set up.",
		Demo:           "guest",
	},
	{
		Slug:  "paper-visitor-permits",
		Title: "Do visitors need a paper permit in Stonnington? — p.stonn",
		Desc:  "City of Stonnington visitor parking permits are digital by default: nothing to display, but the number plate has to be right before each visitor parks. What that means in practice.",
		H1:    "Do visitors need a paper permit in Stonnington?",
		Paras: []string{
			"Not usually. Permits are digital by default: there's nothing to display, and parking officers check the plate against your permit. Physical permits you already hold stay valid until they expire, and the council will issue one on application in exceptional circumstances — disability, carer arrangements, or limited online access.",
		},
		CouncilHeading: "To see which plate is on your permit now",
		Steps: []template.HTML{
			councilSignInSteps[0],
			template.HTML(`Find the visitor permit in your Current Permit list &mdash; the vehicle shown is the one that&rsquo;s covered right now.`),
			template.HTML(`If it&rsquo;s the wrong car, choose <strong>Update Vehicle</strong> and enter the visitor&rsquo;s registration before they park.`),
		},
		CouncilNote: template.HTML(`Physical permits: see <a href="` + councilVisitor + `" target="_blank" rel="noopener">the council&rsquo;s visitor-permit page</a> for the exceptional-circumstances application, or ring 03 8290 1333.`),
		Pstonn:      "A weekly roster for regulars, one-off bookings for everyone else, a link or QR your visitors use themselves — and a notification each time the plate changes, so you know who's covered.",
		Demo:        "oneoff",
	},
}

func guideBySlug(slug string) *guidePage {
	for i := range guides {
		if guides[i].Slug == slug {
			return &guides[i]
		}
	}
	return nil
}

// guide serves one public question page.
func (s *Server) guide(w http.ResponseWriter, r *http.Request) {
	g := guideBySlug(r.PathValue("slug"))
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
