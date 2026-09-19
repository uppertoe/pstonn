package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// An "empty" day and an "empty" booking are read back as such, a rego written
// over an empty day replaces it, and a copied schedule keeps them. A booking
// with neither a rego nor the empty marker is refused rather than stored as
// something Resolve would have to guess at.
func TestEmptyRulesAndBookings(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const owner = "a@example.com"
	pid, err := s.UpsertPermit(ctx, owner, "P1", "14", "Home")
	if err != nil {
		t.Fatal(err)
	}
	vid, err := s.CreateVehicle(ctx, owner, "ABC123", "Van", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetEmptyRule(ctx, owner, pid, 0, time.Monday); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRule(ctx, owner, pid, 0, time.Tuesday, vid); err != nil {
		t.Fatal(err)
	}
	rules, err := s.ListRules(ctx, pid)
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules = %+v, %v", rules, err)
	}
	if !rules[0].Empty || rules[0].VehicleID != 0 || rules[1].Empty || rules[1].VehicleID != vid {
		t.Fatalf("rules read back wrong: %+v", rules)
	}
	// A rego over the empty day, then empty over the rego day: each replaces.
	if err := s.SetRule(ctx, owner, pid, 0, time.Monday, vid); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEmptyRule(ctx, owner, pid, 0, time.Tuesday); err != nil {
		t.Fatal(err)
	}
	rules, _ = s.ListRules(ctx, pid)
	if rules[0].Empty || rules[0].VehicleID != vid || !rules[1].Empty || rules[1].VehicleID != 0 {
		t.Fatalf("replacement went wrong: %+v", rules)
	}
	// Another owner cannot write an empty day onto this permit.
	if err := s.SetEmptyRule(ctx, "b@example.com", pid, 0, time.Monday); err != ErrNotFound {
		t.Fatalf("cross-owner empty rule = %v, want ErrNotFound", err)
	}

	now := time.Now()
	end := now.Add(2 * time.Hour)
	if _, err := s.CreateEmptyOverride(ctx, pid, now, &end, owner, MaxLiveOverridesPerPermit); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOverrideCapped(ctx, pid, 0, "", "", now, &end, owner, MaxLiveOverridesPerPermit); err == nil {
		t.Fatal("a booking with neither rego nor plate was stored")
	}
	ovs, err := s.ListOverrides(ctx, pid, now)
	if err != nil || len(ovs) != 1 || !ovs[0].Empty || ovs[0].VehicleID != 0 || ovs[0].Registration != "" {
		t.Fatalf("overrides = %+v, %v", ovs, err)
	}

	dst, err := s.UpsertPermit(ctx, owner, "P2", "14", "Second")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.CopySchedule(ctx, owner, pid, dst, now); err != nil || n != 3 {
		t.Fatalf("copy = %d, %v", n, err)
	}
	if rules, _ := s.ListRules(ctx, dst); len(rules) != 2 || !rules[1].Empty {
		t.Fatalf("copied rules = %+v", rules)
	}
	if ovs, _ := s.ListOverrides(ctx, dst, now); len(ovs) != 1 || !ovs[0].Empty {
		t.Fatalf("copied overrides = %+v", ovs)
	}
	// A cycle shrink hands back a clear day as a clear day (its vehicle is
	// NULL, which the old scan choked on), and the restore puts it back.
	if n, err := s.GrowCycle(ctx, owner, pid, "2026-09-06", 2); err != nil || n != 2 {
		t.Fatalf("grow = %d, %v", n, err)
	}
	if err := s.SetEmptyRule(ctx, owner, pid, 1, time.Friday); err != nil {
		t.Fatal(err)
	}
	removed, n, err := s.ShrinkCycle(ctx, owner, pid, "", 1)
	if err != nil || n != 1 {
		t.Fatalf("shrink = %d, %v", n, err)
	}
	clears := 0
	for _, r := range removed {
		if r.Week != 1 {
			t.Fatalf("removed rule from week %d: %+v", r.Week, r)
		}
		if r.Empty && r.Weekday == time.Friday {
			clears++
		}
	}
	if clears != 1 {
		t.Fatalf("the clear day did not come back from the shrink: %+v", removed)
	}
	if n, err := s.RestoreCycle(ctx, owner, pid, removed, "2026-09-06", 2); err != nil || n != 2 {
		t.Fatalf("restore = %d, %v", n, err)
	}
	// Week 1 (a copy of week 0: Monday's rego and Tuesday's clear) plus its
	// own Friday clear are all back.
	if rules, _ := s.ListRules(ctx, pid); len(rules) != 5 || !rules[4].Empty || rules[4].Week != 1 || rules[4].Weekday != time.Friday {
		t.Fatalf("rules after restore = %+v", rules)
	}
	if _, _, err := s.ShrinkCycle(ctx, owner, pid, "", 1); err != nil {
		t.Fatal(err)
	}

	// Deleting the rego takes its day with it (the cascade) and leaves the
	// empty day, which depends on no rego.
	if _, err := s.DeleteVehicle(ctx, owner, vid); err != nil {
		t.Fatal(err)
	}
	if rules, _ := s.ListRules(ctx, pid); len(rules) != 1 || !rules[0].Empty {
		t.Fatalf("rules after the rego went = %+v", rules)
	}
}

// A database from before empty days (weekly_rule.vehicle_id NOT NULL, no
// empty columns) is rebuilt on open, keeping its rows and ids, and then
// accepts an empty day.
func TestMigrateStrictWeeklyRule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strict.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
CREATE TABLE permit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, council_id TEXT NOT NULL DEFAULT 'stonnington',
    council_permit_id TEXT NOT NULL, permit_type_id TEXT NOT NULL DEFAULT '', label TEXT NOT NULL DEFAULT '',
    active_registration TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '', cycle_weeks INTEGER NOT NULL DEFAULT 1,
    cycle_anchor TEXT NOT NULL DEFAULT '', UNIQUE(owner, council_id, council_permit_id)
);
CREATE TABLE vehicle (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, registration TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', UNIQUE(owner, registration));
CREATE TABLE weekly_rule (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id  INTEGER NOT NULL REFERENCES permit(id) ON DELETE CASCADE,
    cycle_week INTEGER NOT NULL DEFAULT 0,
    weekday    INTEGER NOT NULL,
    vehicle_id INTEGER NOT NULL REFERENCES vehicle(id) ON DELETE CASCADE,
    UNIQUE(permit_id, cycle_week, weekday)
);
INSERT INTO permit (id, owner, council_permit_id) VALUES (1, 'a@example.com', 'P1');
INSERT INTO vehicle (id, owner, registration, label) VALUES (5, 'a@example.com', 'ABC123', 'Van');
INSERT INTO weekly_rule (id, permit_id, cycle_week, weekday, vehicle_id) VALUES (9, 1, 0, 2, 5);
`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open strict db: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	rules, err := s.ListRules(ctx, 1)
	if err != nil || len(rules) != 1 || rules[0].ID != 9 || rules[0].VehicleID != 5 || rules[0].Empty {
		t.Fatalf("rules after rebuild = %+v, %v", rules, err)
	}
	if strict, _ := s.weeklyRuleVehicleIsNotNull(); strict {
		t.Fatal("weekly_rule still declares vehicle_id NOT NULL")
	}
	if err := s.SetEmptyRule(ctx, "a@example.com", 1, 0, time.Monday); err != nil {
		t.Fatalf("empty day on the rebuilt table: %v", err)
	}
}
