package server

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
)

// The permit card shows what happens next: the booking in charge is marked,
// one covered by a newer booking is marked as waiting, the plate that takes
// over when the booking in charge ends sits under "on the permit now", and each
// cancel confirm names the plate it leaves (a household on 2026-11-13 kept a
// long booking as the permit's usual car under short ones).
func TestPermitCardShowsWhatComesNext(t *testing.T) {
	ctx := context.Background()
	type rig struct {
		build func() permitView
		car   func(reg string) int64
		book  func(vid int64, from, to time.Time) int64
		set   func(vid int64)
		now   time.Time
	}
	newRig := func(t *testing.T, owner, onPermit string) rig {
		t.Helper()
		r := newTenantRig(t)
		loc := r.s.locFor(ctx, owner)
		now := time.Now().In(loc)
		id, err := r.st.UpsertPermit(ctx, owner, "NEXT-1", "1", "Front")
		if err != nil {
			t.Fatal(err)
		}
		p := model.Permit{ID: id, Owner: owner, TenantID: r.s.registry.Default.ID, CouncilPermitID: "NEXT-1", PermitTypeID: "1", ActiveRegistration: onPermit}
		return rig{
			now: now,
			build: func() permitView {
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
			},
			car: func(reg string) int64 {
				t.Helper()
				vid, err := r.st.CreateVehicle(ctx, owner, reg, reg, "")
				if err != nil {
					t.Fatal(err)
				}
				return vid
			},
			book: func(vid int64, from, to time.Time) int64 {
				t.Helper()
				oid, err := r.st.CreateOverride(ctx, id, vid, from, &to, owner)
				if err != nil {
					t.Fatal(err)
				}
				return oid
			},
			set: func(vid int64) {
				t.Helper()
				for wd := time.Sunday; wd <= time.Saturday; wd++ {
					if err := r.st.SetRule(ctx, owner, id, 0, wd, vid); err != nil {
						t.Fatal(err)
					}
				}
			},
		}
	}
	byID := func(pv permitView, oid int64) overrideView {
		for _, o := range pv.Overrides {
			if o.ID == oid {
				return o
			}
		}
		t.Fatalf("booking %d not on the card", oid)
		return overrideView{}
	}

	t.Run("a short booking over a long one", func(t *testing.T) {
		g := newRig(t, "stack@example.com", "ZBN603")
		usual, visitor := g.car("CJV604"), g.car("ZBN603")
		long := g.book(usual, g.now.Add(-time.Hour), g.now.AddDate(0, 6, 0))
		short := g.book(visitor, g.now.Add(-time.Minute), g.now.Add(2*time.Hour))
		pv := g.build()

		if o := byID(pv, short); !o.Now || o.Under || o.CancelPlate != "CJV604" || o.CancelLabel != "goes back on." {
			t.Fatalf("short booking = %+v, want in charge, cancelling puts CJV604 back", o)
		}
		if o := byID(pv, long); o.Now || !o.Under || o.CancelPlate != "" || o.CancelNote != "Nothing changes now." {
			t.Fatalf("long booking = %+v, want covered, cancelling changes nothing now", o)
		}
		if pv.Next == nil || pv.Next.Reg != "CJV604" || pv.Next.At == "" {
			t.Fatalf("Next = %+v, want CJV604 when the short booking ends", pv.Next)
		}
		var buf bytes.Buffer
		if err := templates.ExecuteTemplate(&buf, "permit-body", pv); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		for _, want := range []string{`class="nownext"`, `>CJV604</span><span class="muted">from `, `oneoff-item is-now`, `oneoff-item is-under`,
			`data-confirm-plate="CJV604"`, `data-confirm-plate-label="goes back on."`, `hx-confirm="Cancel this booking? Nothing changes now."`} {
			if !strings.Contains(out, want) {
				t.Errorf("card missing %q", want)
			}
		}
	})

	t.Run("a booking over the roster", func(t *testing.T) {
		g := newRig(t, "roster@example.com", "VIS001")
		home, visitor := g.car("HOME01"), g.car("VIS001")
		g.set(home)
		oid := g.book(visitor, g.now.Add(-time.Minute), g.now.Add(2*time.Hour))
		pv := g.build()
		if o := byID(pv, oid); !o.Now || o.CancelPlate != "HOME01" || o.CancelLabel != "goes back on." {
			t.Fatalf("booking = %+v, want cancelling to put the roster's HOME01 back", o)
		}
		if pv.Next == nil || pv.Next.Reg != "HOME01" {
			t.Fatalf("Next = %+v, want the roster's HOME01", pv.Next)
		}
	})

	t.Run("a lone booking leaves its plate on", func(t *testing.T) {
		g := newRig(t, "lone@example.com", "VIS002")
		oid := g.book(g.car("VIS002"), g.now.Add(-time.Minute), g.now.Add(2*time.Hour))
		pv := g.build()
		if o := byID(pv, oid); !o.Now || o.CancelPlate != "VIS002" || o.CancelLabel != "stays on." {
			t.Fatalf("booking = %+v, want cancelling to leave VIS002 on", o)
		}
		if pv.Next != nil {
			t.Fatalf("Next = %+v, want none: nothing different follows", pv.Next)
		}
	})

	t.Run("a booking that has not started", func(t *testing.T) {
		g := newRig(t, "later@example.com", "")
		oid := g.book(g.car("LATER1"), g.now.Add(24*time.Hour), g.now.Add(26*time.Hour))
		pv := g.build()
		if o := byID(pv, oid); o.Now || o.Under || o.CancelPlate != "" || o.CancelNote != "" {
			t.Fatalf("future booking = %+v, want no marks and a plain confirm", o)
		}
	})
}

func TestNextAtLabel(t *testing.T) {
	loc, err := time.LoadLocation("Australia/Melbourne")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 13, 16, 50, 0, 0, loc)
	for _, c := range []struct {
		at   time.Time
		want string
	}{
		{time.Date(2026, 11, 14, 0, 0, 0, 0, loc), "midnight"},
		{time.Date(2026, 11, 13, 18, 30, 0, 0, loc), "6:30pm"},
		{time.Date(2027, 7, 1, 0, 0, 0, 0, loc), "Thu 1 Jul"},
		{time.Date(2026, 11, 15, 9, 0, 0, 0, loc), "Sun 15 Nov, 9:00am"},
	} {
		if got := nextAtLabel(now, c.at); got != c.want {
			t.Errorf("nextAtLabel(%s) = %q, want %q", c.at, got, c.want)
		}
	}
}
