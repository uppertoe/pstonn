package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/model"
)

// The "on permit now" badge used to spin on nearly every daily visit: the plate
// cache is process memory with a 5-minute life, so the first render of the day
// found nothing and showed "checking" until a governed council read landed and
// the (5s-first) poll picked it up. These tests pin the replacement: a plate the
// council confirmed recently leads with its tick and a quiet age hint while the
// refresh runs, the spinner is reserved for "nothing recent to lean on", and the
// honesty states (applying, couldn't check) still win over both.

// TestPlateBadgeTiers renders the badge in each tier and checks what the reader
// sees — including what they must NOT see, which a substring golden can't say.
func TestPlateBadgeTiers(t *testing.T) {
	loc := melbourne(t)
	const spinner = `class="pchk"`
	const tick = `class="pok"`
	const warn = `class="pwarn"`
	cases := []struct {
		name    string
		mut     func(*permitView)
		want    []string
		notWant []string
	}{
		{"fresh: settled tick, age hint, no poll", func(pv *permitView) { pv.PlateCheckedAgo = "checked just now" },
			[]string{tick, "Checked against the council record", "checked just now"},
			[]string{spinner, warn, "/permits/7/card"}},
		{"recently confirmed: spinner (read in flight, never the green tick), age hint, poll still armed", func(pv *permitView) {
			pv.PlateRefreshing, pv.PlateRecent, pv.PlateCheckedAgo = true, true, "checked 2 hr ago"
		},
			[]string{spinner, "checked 2 hr ago", "Last confirmed by the council", `hx-get="/permits/7/card?n=1"`},
			[]string{tick, warn}},
		{"old reading: spinner", func(pv *permitView) { pv.PlateRefreshing = true },
			[]string{spinner, "Checking the council record", "checking&hellip;", `hx-get="/permits/7/card?n=1"`},
			[]string{tick, "checked "}},
		{"nothing known: spinner", func(pv *permitView) { pv.PlateRefreshing, pv.PlateCheckedAgo = true, "" },
			[]string{spinner},
			[]string{tick, "checked "}},
		{"applying beats recent: applying spinner, no age hint", func(pv *permitView) {
			pv.Applying, pv.PlateRefreshing, pv.PlateRecent, pv.PlateCheckedAgo = true, true, true, "checked 2 hr ago"
		},
			[]string{"Applying your change", "applying&hellip;"},
			[]string{tick, "checked 2 hr ago"}},
		{"budget spent beats recent: honest couldn't-check mark", func(pv *permitView) {
			pv.PlateRefreshing, pv.PlateRecent, pv.PlateCheckedAgo = true, true, "checked 2 hr ago"
			pv.pollSeed = len(platePollDelays)
		},
			[]string{warn, "couldn&rsquo;t check"},
			[]string{tick, spinner, "checked 2 hr ago", "/permits/7/card"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pv := samplePermitView(loc)
			c.mut(&pv)
			pv.armPlatePoll(0)
			var buf bytes.Buffer
			if err := templates.ExecuteTemplate(&buf, "permit-body", pv); err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("badge missing %q", w)
				}
			}
			for _, nw := range c.notWant {
				if strings.Contains(out, nw) {
					t.Errorf("badge must not contain %q", nw)
				}
			}
		})
	}
}

// TestBuildPermitViewPlateTiers drives the real view builder with a COLD plate
// cache (nothing fetched this process) and only the persisted stamp to go on —
// the daily-visit case. The tier must come from the stamp's age, the refresh
// must still be kicked (the poll is armed) so drift is caught, and "applying"
// must be decided independently of it.
func TestBuildPermitViewPlateTiers(t *testing.T) {
	r := newTenantRig(t)
	ctx := context.Background()
	const owner = "cold@example.com"
	loc := r.s.locFor(ctx, owner)
	now := time.Now().In(loc)
	id, err := r.st.UpsertPermit(ctx, owner, "COLD-1", "1", "Front")
	if err != nil {
		t.Fatal(err)
	}
	base := model.Permit{ID: id, Owner: owner, TenantID: r.s.registry.Default.ID, CouncilPermitID: "COLD-1", PermitTypeID: "1", ActiveRegistration: "ABC123"}
	build := func(p model.Permit) permitView {
		t.Helper()
		vs, err := r.st.ListVehiclesFor(ctx, owner)
		if err != nil {
			t.Fatal(err)
		}
		vviews, colorByID, regByID, labelByID := vehicleViews(vs)
		pv, err := r.s.buildPermitView(ctx, p, vviews, colorByID, regByID, labelByID, now)
		if err != nil {
			t.Fatal(err)
		}
		return pv
	}

	t.Run("confirmed 2h ago: tick with hint, refresh kicked", func(t *testing.T) {
		p := base
		p.ActiveConfirmedAt = now.Add(-2 * time.Hour)
		pv := build(p)
		if !pv.PlateRefreshing || !pv.PlateRecent || pv.PlateCheckedAgo != "checked 2 hr ago" {
			t.Fatalf("refreshing=%v recent=%v hint=%q; want refreshing, recent, \"confirmed 2 hr ago · checking…\"", pv.PlateRefreshing, pv.PlateRecent, pv.PlateCheckedAgo)
		}
		// PollNext may sit past 1: the rig's owner holds no council session, so the
		// kicked refresh fails at once and RefreshFailingFor seeds the honesty clock.
		if pv.PollNext < 1 || pv.PollDelay <= 0 {
			t.Fatalf("poll not armed on a recently-confirmed cold render (PollNext=%d PollDelay=%d): the background refresh would never swap in", pv.PollNext, pv.PollDelay)
		}
		if pv.Applying || pv.PlateUnconfirmed {
			t.Fatalf("settled schedule flagged applying=%v unconfirmed=%v", pv.Applying, pv.PlateUnconfirmed)
		}
	})
	t.Run("confirmed 20h ago: too old to lead with, spinner", func(t *testing.T) {
		p := base
		p.ActiveConfirmedAt = now.Add(-20 * time.Hour)
		pv := build(p)
		if !pv.PlateRefreshing || pv.PlateRecent || pv.PlateCheckedAgo != "" {
			t.Fatalf("refreshing=%v recent=%v hint=%q; want refreshing only", pv.PlateRefreshing, pv.PlateRecent, pv.PlateCheckedAgo)
		}
	})
	t.Run("never confirmed: spinner", func(t *testing.T) {
		pv := build(base)
		if !pv.PlateRefreshing || pv.PlateRecent {
			t.Fatalf("refreshing=%v recent=%v; want refreshing only", pv.PlateRefreshing, pv.PlateRecent)
		}
	})
	t.Run("applying: a schedule wanting another plate", func(t *testing.T) {
		vid, err := r.st.CreateVehicle(ctx, owner, "XYZ789", "Mum", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := r.st.SetRule(ctx, id, 0, now.Weekday(), vid); err != nil {
			t.Fatal(err)
		}
		p := base
		p.ActiveConfirmedAt = now.Add(-time.Hour)
		pv := build(p)
		if !pv.Applying {
			t.Fatal("roster wants XYZ789 while ABC123 is confirmed: view must be Applying")
		}
		if pv.PollNext < 1 {
			t.Fatalf("applying card must poll, PollNext=%d", pv.PollNext)
		}
	})
}

// TestPermitCardPollCarriesNoScheduleChanged: the badge's self-poll is a read.
// It used to reply with HX-Trigger: schedule-changed like every mutation, so each
// tick also re-fetched the legend — two requests per check for a key that could
// not have moved. Mutations must still carry it (the legend lives outside the
// card's swap target and only refreshes on that trigger).
func TestPermitCardPollCarriesNoScheduleChanged(t *testing.T) {
	r := newTenantRig(t)
	ctx := context.Background()
	const user = "poll@example.com"
	r.consent(t, user)
	id, err := r.st.UpsertPermit(ctx, user, "POLL-1", "1", "Front")
	if err != nil {
		t.Fatal(err)
	}
	hx := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		var body = strings.NewReader("")
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req := httptest.NewRequest(method, path, body)
		req.Host = "app.example.com"
		req.RemoteAddr = "10.0.0.2:41000"
		req.Header.Set("Remote-Email", user)
		req.Header.Set("Remote-Groups", "user")
		req.Header.Set("HX-Request", "true")
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", "https://app.example.com")
		}
		rr := httptest.NewRecorder()
		r.s.Handler().ServeHTTP(rr, req)
		return rr
	}
	card := "/permits/" + strconv.FormatInt(id, 10)

	rr := hx(http.MethodGet, card+"/card?n=1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET card = %d: %s", rr.Code, excerpt(rr.Body.String()))
	}
	if got := rr.Header().Get("HX-Trigger"); got != "" {
		t.Fatalf("the poll replied HX-Trigger %q; a read must not make the page re-fetch the legend", got)
	}
	if !strings.Contains(rr.Body.String(), `class="nowbadge"`) {
		t.Fatalf("poll reply lacks the badge it exists to refresh: %s", excerpt(rr.Body.String()))
	}

	rr = hx(http.MethodPost, card+"/rules", url.Values{"weekday": {"1"}, "vehicle_id": {"0"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("POST rules = %d: %s", rr.Code, excerpt(rr.Body.String()))
	}
	if got := rr.Header().Get("HX-Trigger"); got != "schedule-changed" {
		t.Fatalf("a roster edit replied HX-Trigger %q, want schedule-changed (the legend would go stale)", got)
	}
}

// TestOneOffModalGuardIgnoresPoll pins the client-side guard that closes the
// one-off modal: it must key on a SUCCESSFUL NON-GET (a form submit that landed),
// because the badge's timer poll is a GET that bubbles through the same section
// and used to close a modal the person was typing into. The behaviour itself is
// browser-side (see the manual check in the report); this locks the expression.
func TestOneOffModalGuardIgnoresPoll(t *testing.T) {
	loc := melbourne(t)
	var page bytes.Buffer
	if err := templates.ExecuteTemplate(&page, "dashboard", dashboardData{
		User: identity.User{Email: "a@b.com"}, State: "app", Page: "schedule", Loc: loc,
		Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
		App:      &appData{Permits: []permitView{samplePermitView(loc)}},
	}); err != nil {
		t.Fatal(err)
	}
	out := page.String()
	i := strings.Index(out, `@htmx:after-request="`)
	if i < 0 {
		t.Fatal("schedule page has no after-request guard on the permit section")
	}
	guard := out[i:]
	guard = guard[:strings.Index(guard, `">`)+1]
	for _, want := range []string{"$event.detail.successful", "requestConfig.verb !== 'get'", "addOpen=false"} {
		if !strings.Contains(guard, want) {
			t.Errorf("modal guard %q lacks %q — the badge poll (a GET) would close an open modal again", guard, want)
		}
	}
}
