package server

import (
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/store"
)

// Golden renders: the shape lock for the multi-tenant decoupling
// (docs/council-connections.md). Every page state, every htmx fragment and every
// public HTTP response is rendered from fixed fixtures at a pinned clock and
// compared byte-for-byte with the file under testdata/golden/. A refactor that
// changes ANY output fails here with a diff, so "no behaviour change" is checked,
// not asserted.
//
// Regenerate deliberately, in a commit that touches nothing else, so the diff of
// the goldens IS the review of the copy change:
//
//	go test ./internal/server -run Golden -update
//
// The set is locked both ways: a case with no golden fails (add one with -update),
// and a golden with no case fails (a case was removed — delete the file).

var updateGolden = flag.Bool("update", false, "rewrite the golden files from the current render")

const goldenRoot = "testdata/golden"

// goldenNow is the pinned clock. Melbourne winter, a Monday afternoon: no DST
// edge, and a weekday so roster/calendar fixtures read naturally.
func goldenClock(t *testing.T) (time.Time, *time.Location) {
	loc := melbourne(t)
	return time.Date(2026, time.August, 10, 14, 30, 0, 0, loc), loc
}

// goldenSlug turns a case name into a stable file name.
var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func goldenSlug(name string) string {
	return strings.Trim(slugRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

// goldenCheck compares got with the golden file at rel (under goldenRoot) and
// records the file as seen. With -update it writes instead.
type goldenSet struct {
	t    *testing.T
	seen map[string]bool
}

func newGoldenSet(t *testing.T) *goldenSet { return &goldenSet{t: t, seen: map[string]bool{}} }

func (g *goldenSet) check(rel string, got []byte) {
	g.t.Helper()
	path := filepath.Join(goldenRoot, rel)
	if g.seen[rel] {
		g.t.Fatalf("golden %s produced twice: two cases share a name", rel)
	}
	g.seen[rel] = true
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			g.t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			g.t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		g.t.Errorf("no golden for %s (run with -update to create it): %v", rel, err)
		return
	}
	if !bytes.Equal(want, got) {
		g.t.Errorf("%s differs from its golden:\n%s", rel, firstDiff(string(want), string(got)))
	}
}

// finish fails on goldens under dir that no case produced.
func (g *goldenSet) finish(dir string) {
	g.t.Helper()
	root := filepath.Join(goldenRoot, dir)
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(goldenRoot, path)
		if !g.seen[rel] {
			g.t.Errorf("stale golden %s: no case produces it (delete it if the case was removed)", rel)
		}
		return nil
	})
}

// firstDiff shows the first differing line with a little context, and a count of
// how many lines differ overall, so a one-word copy change reads as one.
func firstDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	n := len(wl)
	if len(gl) > n {
		n = len(gl)
	}
	var first = -1
	diffs := 0
	for i := 0; i < n; i++ {
		var a, b string
		if i < len(wl) {
			a = wl[i]
		}
		if i < len(gl) {
			b = gl[i]
		}
		if a != b {
			diffs++
			if first < 0 {
				first = i
			}
		}
	}
	if first < 0 {
		return "(identical lines; trailing whitespace or newline differs)"
	}
	var a, b string
	if first < len(wl) {
		a = wl[first]
	}
	if first < len(gl) {
		b = gl[first]
	}
	return fmt.Sprintf("%d line(s) differ; first at line %d:\n- %s\n+ %s", diffs, first+1, a, b)
}

// TestGoldenPages renders every page state and fragment.
func TestGoldenPages(t *testing.T) {
	now, loc := goldenClock(t)
	user := identity.User{Email: "a@b.com"}
	tm := loadTerms("")
	g := newGoldenSet(t)

	cases := templateRenderCases(loc, user, tm, now)
	cases = append(cases, goldenExtraCases(loc, user, now)...)
	names := map[string]bool{}
	for _, c := range cases {
		slug := goldenSlug(c.name)
		if names[slug] {
			t.Fatalf("two page cases slug to %q", slug)
		}
		names[slug] = true
		var buf bytes.Buffer
		if err := templates.ExecuteTemplate(&buf, "dashboard", c.data); err != nil {
			t.Fatalf("render %s: %v", c.name, err)
		}
		g.check(filepath.Join("pages", slug+".html"), buf.Bytes())
	}

	// Fragments swapped in by htmx.
	for _, fc := range permitBodyCases(loc, now) {
		var buf bytes.Buffer
		if err := templates.ExecuteTemplate(&buf, "permit-body", fc.pv()); err != nil {
			t.Fatalf("render permit-body/%s: %v", fc.name, err)
		}
		g.check(filepath.Join("fragments", "permit-body-"+goldenSlug(fc.name)+".html"), buf.Bytes())
	}
	for _, fc := range goldenFragmentCases(loc, user, now) {
		var buf bytes.Buffer
		if err := templates.ExecuteTemplate(&buf, fc.tmpl, fc.data); err != nil {
			t.Fatalf("render %s/%s: %v", fc.tmpl, fc.name, err)
		}
		g.check(filepath.Join("fragments", fc.tmpl+"-"+goldenSlug(fc.name)+".html"), buf.Bytes())
	}
	g.finish("pages")
	g.finish("fragments")
}

// goldenExtraCases covers the states the substring suite does not: the operator
// page and the public token-driven pages (confirm, decide, unsubscribe, wait,
// message, door QR, FAQ).
func goldenExtraCases(loc *time.Location, user identity.User, now time.Time) []renderCase {
	// The registration-state selector and the interstate chip are provider-agnostic
	// UI: the harness supplies a representative region set (home first) and one
	// interstate vehicle so both are locked in the shape.
	regions := []provider.Region{{Code: "VIC", Label: "VIC"}, {Code: "NSW", Label: "NSW"}, {Code: "SA", Label: "SA"}}
	app := func(page string, extra func(*dashboardData)) dashboardData {
		pv := samplePermitViewAt(loc, now)
		pv.Regions = regions
		d := dashboardData{User: user, State: "app", Page: page, IsPrimary: true, Loc: loc, LogoutURL: "https://auth.example.com/logout",
			Regions:  regions,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb", State: "NSW"}},
			App:      &appData{Permits: []permitView{pv}}}
		if extra != nil {
			extra(&d)
		}
		return d
	}
	return []renderCase{
		{"faq", dashboardData{State: "faq", Loc: loc, Contact: true, FAQ: faqFor(defaultTenantView)}, ""},
		{"faq signed in", dashboardData{State: "faq", Loc: loc, SignedIn: true, FAQ: faqFor(defaultTenantView)}, ""},
		{"message plain", dashboardData{State: "message", Loc: loc, Contact: true, Message: &messageView{Text: "Something happened."}}, ""},
		{"message with link", dashboardData{State: "message", Loc: loc, Message: &messageView{Text: "Done.", LinkLabel: "Back to schedule", LinkHref: "/schedule", After: "or close this tab."}}, ""},
		{"confirm ask", dashboardData{State: "confirm", Loc: loc, Confirm: &confirmView{Token: "tok", Until: "15 Oct 2026"}}, ""},
		{"confirm done", dashboardData{State: "confirm", Loc: loc, Confirm: &confirmView{Token: "tok", Done: true}}, ""},
		{"confirm stale", dashboardData{State: "confirm", Loc: loc, Confirm: &confirmView{Stale: true}}, ""},
		{"unsubscribe ask", dashboardData{State: "unsubscribe", Loc: loc, Contact: true, Unsub: &unsubView{Address: "x@example.com", Path: "/u/x/tok"}}, ""},
		{"unsubscribe done", dashboardData{State: "unsubscribe", Loc: loc, Unsub: &unsubView{Address: "x@example.com", Path: "/u/x/tok", Done: true}}, ""},
		{"guestdecide pending", dashboardData{State: "guestdecide", Loc: loc, Contact: true, Decide: &decideView{Plate: "GUEST1", PermitLabel: "Visitor Permit", Requested: "Mon 10 Aug, 2:15pm", Path: "/r/4/x/tok", Status: "pending", Viewer: "mum@example.com"}}, ""},
		{"guestdecide approved", dashboardData{State: "guestdecide", Loc: loc, Decide: &decideView{Plate: "GUEST1", PermitLabel: "Visitor Permit", Requested: "Mon 10 Aug, 2:15pm", Path: "/r/4/x/tok", Status: "approved", DecidedBy: "mum@example.com", Until: "the end of today", Viewer: "mum@example.com", Outcome: "applied"}}, ""},
		{"guestdecide denied", dashboardData{State: "guestdecide", Loc: loc, Decide: &decideView{Plate: "GUEST1", PermitLabel: "Visitor Permit", Requested: "Mon 10 Aug, 2:15pm", Path: "/r/4/x/tok", Status: "denied", DecidedBy: "mum@example.com", Viewer: "mum@example.com", Outcome: "declined"}}, ""},
		{"guestdecide permit gone", dashboardData{State: "guestdecide", Loc: loc, Decide: &decideView{Plate: "GUEST1", Requested: "Mon 10 Aug, 2:15pm", Path: "/r/4/x/tok", Status: "expired", Viewer: "mum@example.com"}}, ""},
		{"guest-wait pending", dashboardData{State: "guest-wait", Loc: loc, Wait: &guestWaitView{OwnerEmail: "held@example.com", Plate: "GUEST1", ReqID: 4, Nonce: "nn", Status: "pending"}}, ""},
		{"guest-wait approved", dashboardData{State: "guest-wait", Loc: loc, Wait: &guestWaitView{OwnerEmail: "held@example.com", Plate: "GUEST1", ReqID: 4, Nonce: "nn", Status: "approved", Until: "the end of today"}}, ""},
		{"guest-wait denied", dashboardData{State: "guest-wait", Loc: loc, Wait: &guestWaitView{OwnerEmail: "held@example.com", Plate: "GUEST1", ReqID: 4, Nonce: "nn", Status: "denied"}}, ""},
		{"guest-wait stalled", dashboardData{State: "guest-wait", Loc: loc, Wait: &guestWaitView{OwnerEmail: "held@example.com", Plate: "GUEST1", ReqID: 4, Nonce: "nn", Status: "stalled"}}, ""},
		{"guest-wait expired", dashboardData{State: "guest-wait", Loc: loc, Wait: &guestWaitView{OwnerEmail: "held@example.com", Plate: "GUEST1", ReqID: 4, Nonce: "nn", Status: "expired"}}, ""},
		{"doorqr", dashboardData{User: user, State: "doorqr", Loc: loc, LogoutURL: "https://auth.example.com/logout",
			DoorQR: &doorQRView{GrantID: 3, PermitLabel: "Visitor Permit", OwnerEmail: "a@b.com", ImageURI: "data:image/png;base64,AAAA", URL: "https://p.stonn.org/g/tok", CreatedAt: "20 Jul 2026"}}, ""},
		{"admin", dashboardData{User: user, State: "admin", Loc: loc, LogoutURL: "https://auth.example.com/logout", Admin: &adminView{
			Total: 3, Linked: 2, WarmOK: 1, Failing: 1, SchedulerLast: "2 min ago", StatusEnabled: true, SESHook: true,
			StageSignedIn: 1, StagePermit: 1, StageApplied: 1,
			Rows: []adminRow{
				{Email: "a@b.com", Status: "ok", StatusLabel: "Linked", Warmed: "10 min ago", RelinkBy: "15 Oct 2026", EmailOn: true, Consent: "2026-07-18", Permits: 1, Plates: "ABC123", Members: 1, LastApply: "success · 2 hr ago", ApplyOK: 42, Stage: "applied"},
				{Email: "c@d.com", Status: "stale", StatusLabel: "Keep-warm stale", Warmed: "9 hr ago", RelinkBy: "1 Sep 2026", NtfyTopic: "pstonn-abc", Permits: 1, Plates: "XYZ789", LastApply: "error · 5 min ago", LastApplyBad: true, Stage: "permit"},
				{Email: "e@f.com", Status: "unlinked", StatusLabel: "Not linked", InvitedBy: "a@b.com", Stage: "signedin"},
			},
			ApplyMix: []applyMixView{
				{Source: "roster", Success: 40, Errors: 2},
				{Source: "override", Success: 6},
				{Source: "guest", Success: 3, Errors: 1},
				{Source: "external", Changed: 2},
			},
			ApplyLog: []store.AdminApplyRecord{
				{ApplyRecord: store.ApplyRecord{PermitID: 7, Registration: "ABC123", Source: "roster", Status: "success", At: now.Add(-2 * time.Hour)}, Owner: "a@b.com"},
				{ApplyRecord: store.ApplyRecord{PermitID: 9, Registration: "XYZ789", Source: "override", Status: "error", Detail: "council temporarily unavailable", At: now.Add(-5 * time.Hour)}, Owner: "c@d.com"},
				{ApplyRecord: store.ApplyRecord{PermitID: 9, Registration: "GUEST1", Source: "guest", Status: "success", At: now.Add(-26 * time.Hour)}, Owner: "c@d.com"},
			},
			Suppressed: []suppressionRow{{Address: "bounce@example.com", Reason: "bounce", Detail: "550 no such user", Ago: "3 days ago", Hits: 2}},
		}}, ""},
		{"admin empty", dashboardData{User: user, State: "admin", Loc: loc, Admin: &adminView{SchedulerLast: "never", SchedulerStale: true}}, ""},
		{"schedule with warn and flash", app("schedule", func(d *dashboardData) { d.Warn = "Couldn't reach the council just now."; d.Flash = "Saved." }), ""},
		{"schedule with legend overflow", app("schedule", func(d *dashboardData) {
			d.App.LegendVehicles = d.Vehicles
			d.App.LegendMore = 3
		}), ""},
		{"activity with changes", app("activity", func(d *dashboardData) {
			d.App.Log = []store.ApplyRecord{
				{PermitID: 7, Registration: "ABC123", Source: "roster", Status: "success", At: now.Add(-2 * time.Hour)},
				{PermitID: 7, Registration: "XYZ789", Source: "override", Status: "error", Detail: "council temporarily unavailable", At: now.Add(-26 * time.Hour)},
			}
			d.App.Changes = []changeView{{Actor: "a@b.com", Text: "added the car ABC123 (Van)", At: now.Add(-3 * 24 * time.Hour)}, {Text: "reconnected automatically", At: now.Add(-5 * 24 * time.Hour)}}
			d.App.LogMore, d.App.ChangesMore = true, true
		}), ""},
		{"activity showing all", app("activity", func(d *dashboardData) { d.App.ShowingAll = true }), ""},
		{"settings full", app("settings", func(d *dashboardData) {
			d.AutoReconnect = true
			d.Settings = &settingsData{TenantLinked: true, RelinkBy: "15 Oct 2026", LastReconnect: "14 Jul 2026, 3:04pm",
				Notify: notifyView{EmailAvailable: true, EmailEnabled: true, NtfyAvailable: true, NtfyEnabled: true, NtfyTopic: "pstonn-abc", NtfyBase: "https://ntfy.example.com", QuietEnabled: true, QuietFrom: 22, QuietUntil: 6}}
			d.Members = []memberView{{Email: "nanny@example.com", Added: "1 Jul 2026"}}
			d.Terms = termsView{Version: "2026-07-18", Accepted: "v2026-07-18 on 18 Jul 2026"}
		}), ""},
		{"guests with links and requests", app("guests", func(d *dashboardData) {
			d.GuestMgmt = &guestMgmt{
				GuestsEnabled:   true,
				PermitOpts:      []permitOpt{{ID: 1, Label: "Visitor Permit"}},
				NewGuestLinks:   []guestLinkView{{Email: "dad@example.com", URL: "https://p.stonn.org/g/tok1"}},
				DoorGrants:      []doorGrantView{{GrantID: 3, PermitLabel: "Visitor Permit", CreatedAt: "20 Jul 2026"}},
				PendingRequests: []guestReqView{{ID: 4, Plate: "GUEST1", PermitLabel: "Visitor Permit", Ago: "2 min ago"}},
			}
		}), ""},
		{"vehicles with email", app("vehicles", func(d *dashboardData) {
			d.Vehicles = []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb", Email: "van@example.com"}, {ID: 2, Label: "Mum", Registration: "AAA111", Color: "#127a49"}}
		}), ""},
		{"vehicles empty", app("vehicles", func(d *dashboardData) { d.Vehicles = nil }), ""},
		{"schedule multi-area", app("schedule", func(d *dashboardData) {
			// Two LINKED areas: the switcher offers "Switch to…" between them, the
			// app-bar shows the current area, and "Connect another area…" leads to the
			// picker for anything still unlinked.
			d.Tenants = []tenantChoice{{ID: "stonnington", Name: "City of Stonnington", Current: true, Linked: true}, {ID: "ryde", Name: "City of Ryde", Linked: true}}
			d.CanConnectArea = true
		}), ""},
		{"connect area", dashboardData{State: "connectarea", User: user, Loc: loc, LogoutURL: "https://auth.example.com/logout",
			Tenants:        []tenantChoice{{ID: "stonnington", Name: "City of Stonnington", Current: true, Linked: true}},
			CanConnectArea: true,
			Areas:          []tenantChoice{{ID: "ryde", Name: "City of Ryde"}, {ID: "othertown", Name: "Othertown Council"}}}, ""},
	}
}

type fragmentRender struct {
	name string
	tmpl string
	data any
}

func goldenFragmentCases(loc *time.Location, user identity.User, now time.Time) []fragmentRender {
	pv := samplePermitViewAt(loc, now)
	return []fragmentRender{
		{"default", "legend", dashboardData{User: user, Loc: loc, Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}}, App: &appData{Permits: []permitView{pv}}}},
		{"email only", "notify-body", notifyView{EmailAvailable: true, EmailEnabled: true}},
		{"both with error", "notify-body", notifyView{EmailAvailable: true, EmailEnabled: true, NtfyAvailable: true, NtfyEnabled: true, NtfyTopic: "pstonn-abc", NtfyBase: "https://ntfy.example.com", Status: "Saved.", Error: "Keep at least one method on"}},
		{"default", "qr-card", dashboardData{Loc: loc, QR: &qrShowView{PermitLabel: "Visitor Permit", ImageURI: template.URL("data:image/png;base64,AAAA"), URL: "https://p.stonn.org/g/tok", StopsAt: "11:59pm"}}},
		{"menu", "guest-body", dashboardData{State: "guest", Loc: loc, Guest: guestActView{
			Token: "tok", OwnerEmail: "held@example.com", PermitLabel: "Visitor Permit", CurrentReg: "ABC123",
			Cars: []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}}, AllowOvernight: true, AllowPlate: true,
			Regions: []provider.Region{{Code: "VIC", Label: "VIC"}, {Code: "NSW", Label: "NSW"}, {Code: "SA", Label: "SA"}}}}},
		{"pending", "guest-req-status", guestWaitView{OwnerEmail: "held@example.com", Plate: "GUEST1", ReqID: 4, Nonce: "nn", Status: "pending"}},
	}
}

// TestGoldenPublicHTTP goes through the real handler for every public GET, so the
// middleware, SEO head, robots/sitemap/manifest and guide pages are locked as
// served, not just as templated. Per-request randomness (the CSP nonce) is masked.
func TestGoldenPublicHTTP(t *testing.T) {
	_, loc := goldenClock(t)
	cfg := &config.Config{PublicBaseURL: "https://p.stonn.org", DisplayLocation: loc, Domain: "stonn.org"}
	s := &Server{cfg: cfg, terms: loadTerms("")}
	h := s.Handler()
	paths := []string{"/", "/how", "/security", "/faq", "/contact", "/robots.txt", "/sitemap.xml", "/site.webmanifest", "/healthz", "/no-such-page"}
	for _, gd := range guidesFor(defaultTenantView) {
		paths = append(paths, "/guide/"+gd.Slug)
	}
	sort.Strings(paths)
	g := newGoldenSet(t)
	for _, p := range paths {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		var out bytes.Buffer
		fmt.Fprintf(&out, "GET %s\nStatus: %d\n", p, rr.Code)
		keys := make([]string, 0, len(rr.Header()))
		for k := range rr.Header() {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&out, "%s: %s\n", k, maskNonce(strings.Join(rr.Header().Values(k), ", ")))
		}
		out.WriteString("\n")
		out.WriteString(maskNonce(rr.Body.String()))
		name := goldenSlug(p)
		if name == "" {
			name = "root"
		}
		g.check(filepath.Join("http", name+".txt"), out.Bytes())
	}
	g.finish("http")
}

var nonceRe = regexp.MustCompile(`(nonce-|nonce=")[A-Za-z0-9+/=_-]+`)

func maskNonce(s string) string { return nonceRe.ReplaceAllString(s, "${1}NONCE") }
