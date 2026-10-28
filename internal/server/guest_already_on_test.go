package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/store"
)

// A guest who presses the car that is already on the permit, under their own
// link's booking and for at least as long, used to save another identical
// booking, re-write the council and send the household another round of
// notices (prod, 2026-10-28: three presses, eight notices for one car). These
// tests pin the press that now changes nothing — across the guest pass, the
// quick picker and the visitor QR — and every neighbouring case that must still
// make a real booking, because a fresh booking there DOES change the outcome.
// A real booking of a car the council already showed still sends no notices:
// nothing on the permit changed (prod, the same evening: the household's quick
// picker re-booked the car a guest pass had put on, and notified everyone).

type alreadyOnRig struct {
	s     *Server
	rp    *recordingProvider
	ctx   context.Context
	owner string
	pid   int64
	car   int64 // XYZ789, the guest's car
	other int64 // ABC123, a second saved car
	sent  int   // notices queued so far that a later press must not add to
}

func newAlreadyOnRig(t *testing.T) *alreadyOnRig {
	t.Helper()
	s, rp := newApplyRig(t)
	isolateGuestBounds(t)
	g := &alreadyOnRig{s: s, rp: rp, ctx: context.Background(), owner: "primary@example.com"}
	if err := s.tenant.Link(g.ctx, g.owner, "", g.owner, "ok", false, true, 0); err != nil {
		t.Fatal(err)
	}
	var err error
	if g.pid, err = s.store.UpsertPermit(g.ctx, g.owner, "90001", "14", "Visitor"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetPermitActive(g.ctx, g.pid, "SBX1AB"); err != nil {
		t.Fatal(err)
	}
	if g.car, err = s.store.CreateVehicle(g.ctx, g.owner, "XYZ789", "Mum", ""); err != nil {
		t.Fatal(err)
	}
	if g.other, err = s.store.CreateVehicle(g.ctx, g.owner, "ABC123", "Dad", ""); err != nil {
		t.Fatal(err)
	}
	// A real notifier, so each case can count the household notices it queued.
	s.notify = notify.New(s.store, nil, "https://push.example", "", "http://app.example.com", "", "", time.UTC, nil, nil)
	if err := s.store.SetNotifyPref(g.ctx, store.NotifyPref{Owner: g.owner, NtfyEnabled: true, NtfyTopic: "t"}); err != nil {
		t.Fatal(err)
	}
	return g
}

// notices returns how many household notices are queued.
func (g *alreadyOnRig) notices(t *testing.T) int {
	t.Helper()
	q, err := g.s.store.DueOutbox(g.ctx, time.Now().Add(72*time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	return len(q)
}

// tokenID resolves a raw link to its token row, to seed a booking as that link.
func (g *alreadyOnRig) tokenID(t *testing.T, raw string) int64 {
	t.Helper()
	gc, err := g.s.store.GuestContextByTokenHash(g.ctx, hashGuestToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	return gc.TokenID
}

// carOn puts the car on the council's record and our belief, as an earlier
// booking would have, without queuing any notice.
func (g *alreadyOnRig) carOn(t *testing.T, reg string) {
	t.Helper()
	g.rp.SetNow("90001", reg)
	if err := g.s.store.SetPermitActive(g.ctx, g.pid, reg); err != nil {
		t.Fatal(err)
	}
	permit, _ := g.s.store.GetPermit(g.ctx, g.pid)
	g.s.tenant.ForgetPermit(g.owner, permit.TenantID, "90001")
}

const keptOn = " is already on the permit. p.stonn will keep it on until "

// pass creates a guest pass for the given cars and returns its raw token.
func (g *alreadyOnRig) pass(t *testing.T, raw string, overnight bool, cars ...int64) string {
	t.Helper()
	if _, err := g.s.store.CreateGuestGrant(g.ctx, g.owner, g.owner, g.pid, "Parents", overnight, cars,
		[]store.GuestRecipient{{Email: raw + "@example.com", TokenHash: hashGuestToken(raw)}}); err != nil {
		t.Fatal(err)
	}
	return raw
}

func (g *alreadyOnRig) press(t *testing.T, raw string, form url.Values) string {
	t.Helper()
	w := g.s.postGuest("/g/"+raw, "203.0.113.20", "", form)
	if w.Code != 200 {
		t.Fatalf("press = %d %s", w.Code, excerpt(w.Body.String()))
	}
	return w.Body.String()
}

func (g *alreadyOnRig) bookings(t *testing.T) int {
	t.Helper()
	ovs, err := g.s.store.ListOverrides(g.ctx, g.pid, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return len(ovs)
}

func (g *alreadyOnRig) applies(t *testing.T) int {
	t.Helper()
	recs, err := g.s.store.ListApplyLogFor(g.ctx, g.owner, 100)
	if err != nil {
		t.Fatal(err)
	}
	return len(recs)
}

// writes returns how many SetVehicle calls reached the provider since the last
// call, and resets the log.
func (g *alreadyOnRig) writes() int {
	g.rp.mu.Lock()
	defer g.rp.mu.Unlock()
	n := len(g.rp.sets)
	g.rp.sets = nil
	return n
}

// unchanged asserts a press saved nothing, wrote nothing, logged nothing and
// queued no notice beyond the ones already counted.
func (g *alreadyOnRig) unchanged(t *testing.T, bookings, applies int) {
	t.Helper()
	if n := g.notices(t); n != g.sent {
		t.Errorf("notices = %d, want %d (a press that changes nothing notified)", n, g.sent)
	}
	if n := g.bookings(t); n != bookings {
		t.Errorf("bookings = %d, want %d (a second identical booking was saved)", n, bookings)
	}
	if n := g.applies(t); n != applies {
		t.Errorf("activity rows = %d, want %d", n, applies)
	}
	if n := g.writes(); n != 0 {
		t.Errorf("%d council write(s) for a press that changes nothing", n)
	}
}

func dayEndIn(t *testing.T, g *alreadyOnRig, days int) time.Time {
	t.Helper()
	permit, err := g.s.store.GetPermit(g.ctx, g.pid)
	if err != nil {
		t.Fatal(err)
	}
	return dayEndLocal(time.Now().In(g.s.locForPermit(g.ctx, permit)), days)
}

func TestGuestPressAlreadyOn(t *testing.T) {
	carForm := func(id int64) url.Values { return url.Values{"vehicle_id": {itoa64(id)}} }

	t.Run("guest pass: a second press of the same car changes nothing", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		raw := g.pass(t, "pass-token-already-on-00000001", true, g.car, g.other)
		if body := g.press(t, raw, carForm(g.car)); !strings.Contains(body, "XYZ789 is now on the permit until the end of today.") {
			t.Fatalf("first press:\n%s", excerpt(body))
		}
		// The control: a press that changes the car tells the household.
		if g.sent = g.notices(t); g.sent == 0 {
			t.Fatal("the first press queued no notice")
		}
		g.writes()
		body := g.press(t, raw, carForm(g.car))
		if !strings.Contains(body, "XYZ789 is already on the permit until the end of today.") {
			t.Fatalf("second press did not say the car is already on:\n%s", excerpt(body))
		}
		g.unchanged(t, 1, 1)
		// And a third, as in prod.
		g.press(t, raw, carForm(g.car))
		g.unchanged(t, 1, 1)
		// The page still shows the car on the permit and still offers the put-back.
		if !strings.Contains(body, `>XYZ789</span> <span class="gnuntil`) || !strings.Contains(body, "back on the permit") {
			t.Fatalf("already-on page lost the current rego or the put-back:\n%s", excerpt(body))
		}
	})

	t.Run("guest pass: an hour later, a cold cache is confirmed with the council", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		raw := g.pass(t, "pass-token-already-on-0000001b", false, g.car)
		g.press(t, raw, carForm(g.car))
		g.sent = g.notices(t)
		g.writes()
		// The prod case: the cached reading has gone, the council still shows the
		// car, so a live read confirms it and nothing is saved or written.
		permit, _ := g.s.store.GetPermit(g.ctx, g.pid)
		g.s.tenant.ForgetPermit(g.owner, permit.TenantID, "90001")
		if body := g.press(t, raw, carForm(g.car)); !strings.Contains(body, "XYZ789 is already on the permit") {
			t.Fatalf("press with a cold cache:\n%s", excerpt(body))
		}
		g.unchanged(t, 1, 1)
	})

	t.Run("guest pass: a different car is a real change", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		raw := g.pass(t, "pass-token-already-on-00000002", false, g.car, g.other)
		g.press(t, raw, carForm(g.car))
		g.writes()
		if body := g.press(t, raw, carForm(g.other)); !strings.Contains(body, "ABC123 is now on the permit") {
			t.Fatalf("switching cars:\n%s", excerpt(body))
		}
		if g.bookings(t) != 2 || g.writes() != 1 {
			t.Fatal("switching cars did not book and write")
		}
		// Back to the first car: the switch is the freshest booking now, so this
		// is a real change too, not "already on".
		if body := g.press(t, raw, carForm(g.car)); !strings.Contains(body, "XYZ789 is now on the permit") {
			t.Fatalf("switching back:\n%s", excerpt(body))
		}
	})

	t.Run("guest pass: ticking overnight extends, so it books", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		raw := g.pass(t, "pass-token-already-on-00000003", true, g.car)
		g.press(t, raw, carForm(g.car))
		g.sent = g.notices(t)
		g.writes()
		body := g.press(t, raw, url.Values{"vehicle_id": {itoa64(g.car)}, "overnight": {"1"}})
		if !strings.Contains(body, "XYZ789"+keptOn+"the end of tomorrow (") {
			t.Fatalf("overnight extension:\n%s", excerpt(body))
		}
		if n := g.bookings(t); n != 2 {
			t.Fatalf("bookings = %d, want 2 (the extension)", n)
		}
		if n := g.notices(t); n != g.sent {
			t.Fatalf("notices = %d, want %d: the car never left the permit", n, g.sent)
		}
	})

	t.Run("guest pass: today-only under an overnight booking changes nothing", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		raw := g.pass(t, "pass-token-already-on-00000004", true, g.car)
		g.press(t, raw, url.Values{"vehicle_id": {itoa64(g.car)}, "overnight": {"1"}})
		g.sent = g.notices(t)
		g.writes()
		body := g.press(t, raw, carForm(g.car))
		if !strings.Contains(body, "XYZ789 is already on the permit until the end of tomorrow (") {
			t.Fatalf("today-only under overnight:\n%s", excerpt(body))
		}
		g.unchanged(t, 1, 1)
	})

	t.Run("guest pass: the household's own booking for the car does not count", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		raw := g.pass(t, "pass-token-already-on-00000005", false, g.car)
		end := dayEndIn(t, g, 0)
		if _, err := g.s.store.CreateOverride(g.ctx, g.pid, g.car, time.Now().Add(-time.Minute), &end, g.owner); err != nil {
			t.Fatal(err)
		}
		g.carOn(t, "XYZ789")
		// The guest's own booking must survive the household deleting theirs,
		// but the car never left the permit, so nobody is told.
		if body := g.press(t, raw, carForm(g.car)); !strings.Contains(body, "XYZ789"+keptOn+"the end of today.") {
			t.Fatalf("press over the household's booking:\n%s", excerpt(body))
		}
		if n := g.bookings(t); n != 2 {
			t.Fatalf("bookings = %d, want 2 (the guest's own)", n)
		}
		if n := g.notices(t); n != 0 {
			t.Fatalf("notices = %d, want 0", n)
		}
	})

	t.Run("guest pass: another link's booking does not count", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		a := g.pass(t, "pass-token-already-on-0000006a", false, g.car)
		b := g.pass(t, "pass-token-already-on-0000006b", false, g.car)
		// Link A's booking, seeded so no notice of it is queued: the prod case is
		// the guest pass's booking from an hour earlier, long past the dedup window.
		end := dayEndIn(t, g, 0)
		if _, err := g.s.store.CreateGuestOverride(g.ctx, g.pid, g.car, time.Now().Add(-time.Hour), &end, "a@example.com", g.tokenID(t, a)); err != nil {
			t.Fatal(err)
		}
		g.carOn(t, "XYZ789")
		// Revoking link A sweeps A's bookings; B's holder must keep theirs. The
		// car never left the permit, so nobody is told.
		if body := g.press(t, b, carForm(g.car)); !strings.Contains(body, "XYZ789"+keptOn+"the end of today.") {
			t.Fatalf("second link's press:\n%s", excerpt(body))
		}
		if n := g.bookings(t); n != 2 {
			t.Fatalf("bookings = %d, want 2", n)
		}
		if n := g.notices(t); n != 0 {
			t.Fatalf("notices = %d, want 0", n)
		}
		g.writes()
		// B pressing again is now B's own repeat.
		if body := g.press(t, b, carForm(g.car)); !strings.Contains(body, "XYZ789 is already on the permit") {
			t.Fatalf("second link's repeat:\n%s", excerpt(body))
		}
		g.unchanged(t, 2, 1)
	})

	t.Run("guest pass: a newer booking in the window means the press still books", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		raw := g.pass(t, "pass-token-already-on-00000007", false, g.car)
		g.press(t, raw, carForm(g.car))
		g.writes()
		// The household books another car for a slot later today, made after the
		// guest's booking, so it would win that slot; a fresh press must beat it.
		start := time.Now().Add(30 * time.Second)
		end := start.Add(30 * time.Second)
		if _, err := g.s.store.CreateOverride(g.ctx, g.pid, g.other, start, &end, g.owner); err != nil {
			t.Fatal(err)
		}
		if body := g.press(t, raw, carForm(g.car)); !strings.Contains(body, "XYZ789"+keptOn) {
			t.Fatalf("press under a newer booking:\n%s", excerpt(body))
		}
		if n := g.bookings(t); n != 3 {
			t.Fatalf("bookings = %d, want 3", n)
		}
	})

	t.Run("guest pass: the council not showing the car means the press writes again", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		raw := g.pass(t, "pass-token-already-on-00000008", false, g.car)
		g.press(t, raw, carForm(g.car))
		g.writes()
		// Someone changed the permit on the council's own site.
		g.rp.SetNow("90001", "OTHER1")
		permit, _ := g.s.store.GetPermit(g.ctx, g.pid)
		g.s.tenant.ForgetPermit(g.owner, permit.TenantID, "90001")
		g.sent = g.notices(t)
		if body := g.press(t, raw, carForm(g.car)); !strings.Contains(body, "XYZ789 is now on the permit") {
			t.Fatalf("press after an outside change:\n%s", excerpt(body))
		}
		// The car really did go back on, so the household hears about it (the
		// dedup window would swallow an identical notice, so check the outbox
		// grew or the earlier one is still the latest word).
		if n := g.notices(t); n < g.sent {
			t.Fatalf("notices shrank: %d < %d", n, g.sent)
		}
		if n := g.writes(); n != 1 {
			t.Fatalf("council writes = %d, want 1", n)
		}
		if cur, _ := g.rp.Current("90001"); cur != "XYZ789" {
			t.Fatalf("council holds %q", cur)
		}
	})

	t.Run("guest pass: after a put-back the car is a real change again", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		raw := g.pass(t, "pass-token-already-on-00000009", false, g.car)
		g.press(t, raw, carForm(g.car))
		if w := g.s.postGuest("/g/"+raw+"/revert", "203.0.113.20", "", url.Values{}); w.Code != 200 || !strings.Contains(w.Body.String(), "SBX1AB is back on the permit") {
			t.Fatalf("revert = %d %s", w.Code, excerpt(w.Body.String()))
		}
		g.writes()
		if body := g.press(t, raw, carForm(g.car)); !strings.Contains(body, "XYZ789 is now on the permit") {
			t.Fatalf("press after put-back:\n%s", excerpt(body))
		}
		if n := g.writes(); n != 1 {
			t.Fatalf("council writes = %d, want 1", n)
		}
	})

	t.Run("quick picker: a double tap changes nothing", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		const raw = "picker-token-already-on-0000010"
		if _, err := g.s.store.CreatePickerGrant(g.ctx, g.owner, g.owner, g.pid, true, false, []int64{g.car, g.other}, hashGuestToken(raw), "sealed"); err != nil {
			t.Fatal(err)
		}
		g.press(t, raw, carForm(g.car))
		g.sent = g.notices(t)
		g.writes()
		if body := g.press(t, raw, carForm(g.car)); !strings.Contains(body, "XYZ789 is already on the permit until the end of today.") {
			t.Fatalf("picker double tap:\n%s", excerpt(body))
		}
		g.unchanged(t, 1, 1)
	})

	t.Run("visitor QR: the same typed plate changes nothing, another state books", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		const raw = "visitor-qr-token-already-on-011"
		if _, err := g.s.store.CreateQRGrant(g.ctx, g.owner, g.owner, g.pid, hashGuestToken(raw), "sealed", time.Hour); err != nil {
			t.Fatal(err)
		}
		if body := g.press(t, raw, url.Values{"plate": {"tdy 123"}}); !strings.Contains(body, "TDY123 is now on the permit") {
			t.Fatalf("typed plate:\n%s", excerpt(body))
		}
		g.sent = g.notices(t)
		g.writes()
		if body := g.press(t, raw, url.Values{"plate": {"TDY123"}}); !strings.Contains(body, "TDY123 is already on the permit until the end of today.") {
			t.Fatalf("same typed plate:\n%s", excerpt(body))
		}
		g.unchanged(t, 1, 1)
		// The same letters registered in another state are another car.
		if body := g.press(t, raw, url.Values{"plate": {"TDY123"}, "plate_state": {"nsw"}}); !strings.Contains(body, "TDY123 is now on the permit") {
			t.Fatalf("same plate, another state:\n%s", excerpt(body))
		}
		if got := g.rp.last(t); got.Region != "NSW" {
			t.Fatalf("provider was handed %+v, want NSW", got)
		}
		// "is now on" above is the real-change path, which notifies; the outbox
		// cannot show it here, because the notice dedup (15 minutes, keyed on the
		// plate but not its state) merges it with the first press's notice.
		if n := g.bookings(t); n != 2 {
			t.Fatalf("bookings = %d, want 2", n)
		}
	})

	t.Run("quick picker over a guest pass's booking: books, tells nobody (prod case)", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		pass := g.pass(t, "pass-token-already-on-00000012", false, g.car)
		const picker = "picker-token-already-on-0000012"
		if _, err := g.s.store.CreatePickerGrant(g.ctx, g.owner, g.owner, g.pid, true, false, []int64{g.car}, hashGuestToken(picker), "sealed"); err != nil {
			t.Fatal(err)
		}
		end := dayEndIn(t, g, 0)
		if _, err := g.s.store.CreateGuestOverride(g.ctx, g.pid, g.car, time.Now().Add(-time.Hour), &end, "parents@example.com", g.tokenID(t, pass)); err != nil {
			t.Fatal(err)
		}
		g.carOn(t, "XYZ789")
		if body := g.press(t, picker, carForm(g.car)); !strings.Contains(body, "XYZ789"+keptOn+"the end of today.") {
			t.Fatalf("picker tap over the pass's booking:\n%s", excerpt(body))
		}
		if n := g.bookings(t); n != 2 {
			t.Fatalf("bookings = %d, want 2 (the picker's own keeps the car covered)", n)
		}
		if n := g.notices(t); n != 0 {
			t.Fatalf("notices = %d, want 0", n)
		}
	})

	t.Run("a car the roster put on: books, tells nobody", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		raw := g.pass(t, "pass-token-already-on-00000013", false, g.car)
		permit, _ := g.s.store.GetPermit(g.ctx, g.pid)
		today := time.Now().In(g.s.locForPermit(g.ctx, permit)).Weekday()
		if err := g.s.store.SetRule(g.ctx, g.owner, g.pid, 0, today, g.car); err != nil {
			t.Fatal(err)
		}
		g.carOn(t, "XYZ789")
		if body := g.press(t, raw, carForm(g.car)); !strings.Contains(body, "XYZ789"+keptOn+"the end of today.") {
			t.Fatalf("press over the roster:\n%s", excerpt(body))
		}
		if g.bookings(t) != 1 || g.notices(t) != 0 {
			t.Fatalf("bookings = %d, notices = %d; want 1 and 0", g.bookings(t), g.notices(t))
		}
	})

	t.Run("a car left on with nothing scheduled: books, tells nobody", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		raw := g.pass(t, "pass-token-already-on-00000014", false, g.car)
		g.carOn(t, "XYZ789")
		if body := g.press(t, raw, carForm(g.car)); !strings.Contains(body, "XYZ789"+keptOn+"the end of today.") {
			t.Fatalf("press over a left-over plate:\n%s", excerpt(body))
		}
		if g.bookings(t) != 1 || g.notices(t) != 0 {
			t.Fatalf("bookings = %d, notices = %d; want 1 and 0", g.bookings(t), g.notices(t))
		}
	})

	t.Run("a left-over car typed in another state is a real change", func(t *testing.T) {
		g := newAlreadyOnRig(t)
		const raw = "visitor-qr-token-already-on-015"
		if _, err := g.s.store.CreateQRGrant(g.ctx, g.owner, g.owner, g.pid, hashGuestToken(raw), "sealed", time.Hour); err != nil {
			t.Fatal(err)
		}
		g.carOn(t, "XYZ789") // the saved car, home state, nothing scheduled
		if body := g.press(t, raw, url.Values{"plate": {"XYZ789"}, "plate_state": {"nsw"}}); !strings.Contains(body, "XYZ789 is now on the permit") {
			t.Fatalf("left-over plate in another state:\n%s", excerpt(body))
		}
		if n := g.notices(t); n == 0 {
			t.Fatal("correcting the state notified nobody")
		}
	})
}
