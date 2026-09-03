package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
)

// outcomesAfter waits for the async deliveries to settle at n outcomes, or
// reports what arrived.
func outcomesAfter(fn *fakeNotifier, n int) []notify.ApplyOutcome {
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := fn.outcomeSnap()
		if len(got) >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestOutageIsOneEpisodeOneNotice drives a permit through the shape of a real
// council outage — transient errors, then the fleet breaker, then errors again,
// then a confirmed block, then recovery — and pins that the household hears
// exactly: one soft notice, one urgent escalation, one "it's over" success. The
// cause flapping between families mints nothing; a later failure is a new
// episode and is told again.
func TestOutageIsOneEpisodeOneNotice(t *testing.T) {
	ctx := context.Background()
	const owner, cid = "episode@example.com", "ep-1"
	st := newStore(t)
	pid, _ := seedActivePermit(t, st, owner, cid, "WANT1", "OLD1")
	fc := &fakeTenant{setErr: transientErr()}
	fn := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: fn})
	s.notifyRetry = 0
	tick := func(n int) {
		for i := 0; i < n; i++ {
			s.clearRetry(pid) // the backoff is not what is under test
			s.reconcileAll(ctx)
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Three transient failures: one soft notice.
	tick(failNotifyThreshold)
	got := outcomesAfter(fn, 1)
	if len(got) != 1 || got[0].OK || got[0].Urgent {
		t.Fatalf("after %d transient failures: outcomes = %+v, want one soft failure", failNotifyThreshold, got)
	}

	// The breaker opens (busy path, its own copy) well past its own threshold,
	// then errors again, then busy again: the cause flaps, the notice does not.
	fc.setErr = parking.ErrCouncilBusy
	tick(busyNotifyThreshold + 2)
	fc.setErr = transientErr()
	tick(4)
	fc.setErr = parking.ErrCouncilBusy
	tick(3)
	if got := outcomesAfter(fn, 2); len(got) != 1 {
		t.Fatalf("cause flapping across families produced %d outcomes, want still 1: %+v", len(got), got)
	}

	// A CONFIRMED block earns the urgent tier once.
	fc.mu.Lock()
	fc.blocked = true
	fc.mu.Unlock()
	tick(2)
	got = outcomesAfter(fn, 2)
	if len(got) != 2 || !got[1].Urgent {
		t.Fatalf("confirmed block: outcomes = %d, want 2 with the second urgent: %+v", len(got), got)
	}
	// Back to a soft cause: no downgrade, nothing new.
	fc.mu.Lock()
	fc.blocked = false
	fc.mu.Unlock()
	tick(3)
	fc.setErr = transientErr()
	tick(3)
	if got := outcomesAfter(fn, 3); len(got) != 2 {
		t.Fatalf("after the urgent notice, softer causes produced %d outcomes, want still 2", len(got))
	}

	// Recovery: the success closes the episode and is flagged as resolving it.
	fc.setErr = nil
	tick(1)
	got = outcomesAfter(fn, 3)
	if len(got) != 3 || !got[2].OK || !got[2].ResolvesFailure {
		t.Fatalf("recovery: outcomes = %+v, want a third, OK, resolving success", got)
	}
	if plate, _, _ := st.FailureEpisode(ctx, pid); plate != "" {
		t.Fatalf("episode still open after success: told plate %q", plate)
	}

	// A fresh failure later is a fresh episode: told again.
	if err := st.SetPermitActive(ctx, pid, "OLD1"); err != nil {
		t.Fatal(err)
	}
	fc.setErr = transientErr()
	tick(failNotifyThreshold)
	if got := outcomesAfter(fn, 4); len(got) != 4 || got[3].OK {
		t.Fatalf("a new episode after recovery: outcomes = %d, want 4 with a fourth soft failure", len(got))
	}
}

// TestDeployDoesNotRetellAnOpenEpisode: a permit mid-outage on the previous build
// has its notice recorded only as a delivered-outcome key, in the old format. The
// first pass on this build must adopt that as "already told" rather than send
// the notice again — the 06:23 duplicate of 2026-09-03.
func TestDeployDoesNotRetellAnOpenEpisode(t *testing.T) {
	ctx := context.Background()
	const owner, cid = "legacy@example.com", "lg-1"
	st := newStore(t)
	pid, _ := seedActivePermit(t, st, owner, cid, "WANT1", "OLD1")
	for _, legacy := range []string{
		"error|WANT1|p.stonn is having trouble reaching the council to update your permit.|2026-09-02", // pre-04e7d99: reason in the key
		"error|WANT1|2026-09-03",   // 04e7d99..f71470e: family|plate|day
		"busy|WANT1|2026-09-03",    // the busy family
		"session|WANT1|2026-09-03", // urgent family
	} {
		if err := st.SetPermitNotifiedKey(ctx, pid, legacy); err != nil {
			t.Fatal(err)
		}
		if err := st.CloseFailureEpisode(ctx, pid); err != nil {
			t.Fatal(err)
		}
		fc := &fakeTenant{setErr: transientErr()}
		fn := &fakeNotifier{on: true, admin: true}
		s := New(st, fc, time.UTC, Options{Notifier: fn})
		s.notifyRetry = 0
		for i := 0; i < failNotifyThreshold+2; i++ {
			s.clearRetry(pid)
			s.reconcileAll(ctx)
			time.Sleep(5 * time.Millisecond)
		}
		if got := outcomesAfter(fn, 1); len(got) != 0 {
			t.Fatalf("legacy key %q: the new build re-told the household: %+v", legacy, got)
		}
		if plate, urgent, _ := st.FailureEpisode(ctx, pid); plate != "WANT1" {
			t.Fatalf("legacy key %q: episode not adopted (plate %q, urgent %v)", legacy, plate, urgent)
		}
		// But a legacy key about ANOTHER plate is not this episode: told.
		if err := st.SetPermitNotifiedKey(ctx, pid, "error|OTHER9|2026-09-03"); err != nil {
			t.Fatal(err)
		}
		if err := st.CloseFailureEpisode(ctx, pid); err != nil {
			t.Fatal(err)
		}
		s.clearRetry(pid)
		s.reconcileAll(ctx)
		if got := outcomesAfter(fn, 1); len(got) != 1 {
			t.Fatalf("legacy key about another plate must not suppress: outcomes = %d, want 1", len(got))
		}
	}
}

// TestOutageNoticesArePlateAgnostic: inside an outage the target plate is
// incidental, so a booking window flipping the want (A, B, A) must not re-notify
// per plate. Ordinary transient failures keep the per-plate rule.
func TestOutageNoticesArePlateAgnostic(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	pid, _ := st.UpsertPermit(ctx, "o@example.com", "14576", "14", "Permit")
	p := model.Permit{ID: pid, Owner: "o@example.com", CouncilPermitID: "14576", Label: "Permit"}
	fn := &fakeNotifier{on: true, admin: true}
	s := New(st, &fakeTenant{}, time.UTC, Options{Notifier: fn})
	s.notifyRetry = 0
	fail := func(reg string, down bool, tier failTier) {
		s.notifyFailure(ctx, p, notify.ApplyOutcome{Owner: p.Owner, PermitLabel: "Permit", Reg: reg, OK: false, CouncilDown: down, Transient: true}, tier)
		time.Sleep(20 * time.Millisecond)
	}
	fail("AAA111", true, tierSoft) // council down: told once
	fail("BBB222", true, tierSoft) // booking flips the plate mid-outage: same episode
	fail("AAA111", true, tierSoft)
	if n := len(fn.appliedSnap()); n != 1 {
		t.Fatalf("outage notices across a plate flip = %d, want 1", n)
	}
	fail("CCC333", false, tierUrgent) // a confirmed block escalates once, whatever the plate
	fail("DDD444", false, tierUrgent)
	if n := len(fn.appliedSnap()); n != 2 {
		t.Fatalf("urgent escalations = %d total notices, want 2", n)
	}
	// A plain transient failure for a plate not yet told is a new exposure.
	fail("EEE555", false, tierSoft)
	if n := len(fn.appliedSnap()); n != 3 {
		t.Fatalf("a plain failure on a new plate = %d total notices, want 3", n)
	}
	fail("EEE555", false, tierSoft)
	if n := len(fn.appliedSnap()); n != 3 {
		t.Fatalf("repeat of the same plain failure = %d total notices, want still 3", n)
	}
}
