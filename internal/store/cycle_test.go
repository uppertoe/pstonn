package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
)

// The cycle grows and shrinks only at its end, in one transaction each way, and
// the remove hands back exactly what the restore needs — the round trip must be
// lossless.
func TestCycleWeekAddRemoveRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := copyStore(t)
	const owner = "owner@example.com"
	src, _, vehID := copyFixture(t, st, owner) // src: Monday+Friday in week 0

	// Add: the new week is a copy of the last one, and the anchor lands.
	n, err := st.AddCycleWeek(ctx, owner, src, "2026-09-06")
	if err != nil || n != 2 {
		t.Fatalf("AddCycleWeek = %d, %v; want 2", n, err)
	}
	rules, err := st.ListRules(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("after add: %d rules, want 4 (both weeks)", len(rules))
	}
	byWeek := map[int]int{}
	for _, r := range rules {
		byWeek[r.Week]++
	}
	if byWeek[0] != 2 || byWeek[1] != 2 {
		t.Fatalf("after add: rules per week = %v, want 2 each", byWeek)
	}
	p, err := st.GetPermit(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	if p.CycleWeeks != 2 || p.CycleAnchor != "2026-09-06" {
		t.Fatalf("permit cycle after add: weeks=%d anchor=%q", p.CycleWeeks, p.CycleAnchor)
	}

	// Edit week 1, then remove it: the removed rules come back out.
	if err := st.ClearRule(ctx, src, 1, time.Friday); err != nil {
		t.Fatal(err)
	}
	removed, n, err := st.RemoveLastCycleWeek(ctx, owner, src, "")
	if err != nil || n != 1 {
		t.Fatalf("RemoveLastCycleWeek = %d, %v; want 1", n, err)
	}
	if len(removed) != 1 || removed[0].Weekday != time.Monday || removed[0].VehicleID != vehID {
		t.Fatalf("removed week = %+v, want the edited week 1 (Monday only)", removed)
	}
	p, _ = st.GetPermit(ctx, src)
	if p.CycleWeeks != 1 || p.CycleAnchor != "" {
		t.Fatalf("permit after remove: weeks=%d anchor=%q, want a plain weekly roster", p.CycleWeeks, p.CycleAnchor)
	}

	// Restore: the week and its rules return under the given anchor.
	n, err = st.RestoreCycleWeek(ctx, owner, src, removed, "2026-09-06")
	if err != nil || n != 2 {
		t.Fatalf("RestoreCycleWeek = %d, %v; want 2", n, err)
	}
	rules, _ = st.ListRules(ctx, src)
	week1 := 0
	for _, r := range rules {
		if r.Week == 1 {
			week1++
			if r.Weekday != time.Monday {
				t.Fatalf("restored day = %v, want Monday", r.Weekday)
			}
		}
	}
	if week1 != 1 {
		t.Fatalf("restored week holds %d rules, want 1", week1)
	}
	p, _ = st.GetPermit(ctx, src)
	if p.CycleWeeks != 2 || p.CycleAnchor != "2026-09-06" {
		t.Fatalf("permit after restore: weeks=%d anchor=%q", p.CycleWeeks, p.CycleAnchor)
	}
}

// The cap and the floor: a fourth add is refused at MaxCycleWeeks, removing the
// only week is refused, and both errors are the typed ErrCycleWeek so the
// handler can say something honest.
func TestCycleWeekBounds(t *testing.T) {
	ctx := context.Background()
	st := copyStore(t)
	const owner = "owner@example.com"
	src, _, _ := copyFixture(t, st, owner)

	if _, _, err := st.RemoveLastCycleWeek(ctx, owner, src, ""); !errors.Is(err, ErrCycleWeek) {
		t.Fatalf("removing the only week: err = %v, want ErrCycleWeek", err)
	}
	for i := 2; i <= model.MaxCycleWeeks; i++ {
		if n, err := st.AddCycleWeek(ctx, owner, src, "2026-09-06"); err != nil || n != i {
			t.Fatalf("add to %d: n=%d err=%v", i, n, err)
		}
	}
	if _, err := st.AddCycleWeek(ctx, owner, src, "2026-09-06"); !errors.Is(err, ErrCycleWeek) {
		t.Fatalf("fifth week: err = %v, want ErrCycleWeek", err)
	}
	// Owner scoping: someone else's permit is not found.
	if _, _, err := st.RemoveLastCycleWeek(ctx, "other@example.com", src, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign owner: err = %v, want ErrNotFound", err)
	}
}

// A stale tab writing to a week the permit no longer has must be refused, not
// silently written as an orphan row that resurfaces when the cycle grows again.
func TestSetRuleRefusesUnreachableWeek(t *testing.T) {
	ctx := context.Background()
	st := copyStore(t)
	const owner = "owner@example.com"
	src, _, vehID := copyFixture(t, st, owner)

	if err := st.SetRule(ctx, src, 1, time.Tuesday, vehID); !errors.Is(err, ErrCycleWeek) {
		t.Fatalf("week 1 on a 1-week roster: err = %v, want ErrCycleWeek", err)
	}
	if _, err := st.AddCycleWeek(ctx, owner, src, "2026-09-06"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRule(ctx, src, 1, time.Tuesday, vehID); err != nil {
		t.Fatalf("week 1 after adding it: %v", err)
	}
	if err := st.SetRule(ctx, src, 2, time.Tuesday, vehID); !errors.Is(err, ErrCycleWeek) {
		t.Fatalf("week 2 on a 2-week roster: err = %v, want ErrCycleWeek", err)
	}
}

// CopySchedule carries the whole cycle — every week's rules AND the permit's
// cycle shape, anchor verbatim so the two stay in phase — while an empty source
// still touches nothing, cycle fields included.
func TestCopyScheduleCarriesTheCycle(t *testing.T) {
	ctx := context.Background()
	st := copyStore(t)
	const owner = "owner@example.com"
	src, dst, vehID := copyFixture(t, st, owner)

	if _, err := st.AddCycleWeek(ctx, owner, src, "2026-09-06"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRule(ctx, src, 1, time.Wednesday, vehID); err != nil {
		t.Fatal(err)
	}
	n, err := st.CopySchedule(ctx, owner, src, dst, time.Now())
	if err != nil || n == 0 {
		t.Fatalf("copy: n=%d err=%v", n, err)
	}
	rules, err := st.ListRules(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	byWeek := map[int]int{}
	for _, r := range rules {
		byWeek[r.Week]++
	}
	if byWeek[0] != 2 || byWeek[1] != 3 {
		t.Fatalf("copied rules per week = %v, want week0=2 week1=3", byWeek)
	}
	d, err := st.GetPermit(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	if d.CycleWeeks != 2 || d.CycleAnchor != "2026-09-06" {
		t.Fatalf("destination cycle: weeks=%d anchor=%q, want the source's", d.CycleWeeks, d.CycleAnchor)
	}

	// An empty source is a documented no-op — including the cycle fields, or the
	// guard would protect the roster while quietly rewriting its shape.
	empty, err := st.UpsertPermit(ctx, owner, "empty-permit", "14", "Empty")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := st.CopySchedule(ctx, owner, empty, dst, time.Now()); err != nil || n != 0 {
		t.Fatalf("empty copy: n=%d err=%v", n, err)
	}
	d, _ = st.GetPermit(ctx, dst)
	if d.CycleWeeks != 2 || d.CycleAnchor != "2026-09-06" {
		t.Fatalf("empty copy touched the cycle: weeks=%d anchor=%q", d.CycleWeeks, d.CycleAnchor)
	}
}

// The delete-a-car warning must name the week as well as the day on a cycling
// roster — four Tuesdays exist there, and the bare day name under-describes
// what was emptied.
func TestVehicleUsageReportsCycleWeeks(t *testing.T) {
	ctx := context.Background()
	st := copyStore(t)
	const owner = "owner@example.com"
	src, _, vehID := copyFixture(t, st, owner)
	if _, err := st.AddCycleWeek(ctx, owner, src, "2026-09-06"); err != nil {
		t.Fatal(err)
	}
	u, err := st.VehicleUsageFor(ctx, owner, vehID)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Rules) != 4 {
		t.Fatalf("usage rules = %d, want 4 (2 days × 2 weeks)", len(u.Rules))
	}
	seenWeek1 := false
	for _, r := range u.Rules {
		if r.CycleWeeks != 2 {
			t.Fatalf("rule %+v carries CycleWeeks %d, want 2", r, r.CycleWeeks)
		}
		if r.Week == 1 {
			seenWeek1 = true
		}
	}
	if !seenWeek1 {
		t.Fatal("no week-1 rule reported")
	}
}

// The version fence: a file stamped by a NEWER build refuses to open, because
// this build's Resolve would read every cycle week's rules and could write the
// wrong week's car to the council.
func TestSchemaVersionFenceRefusesNewerFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fence.db")
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE schema_migration SET version = ? WHERE id = 1`, schemaVersion+1); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, err := OpenSQLite(path); err == nil || !strings.Contains(err.Error(), "newer build") {
		t.Fatalf("a future-versioned file must refuse to open: %v", err)
	}
}
