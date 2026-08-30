package server

import "testing"

// armPlatePoll is the guard that lets a just-made change (and a slow cold tenant
// read) refresh into the card without letting a tenant outage poll forever. All the
// halves matter, so they are pinned here.
func TestArmPlatePoll(t *testing.T) {
	cap := len(platePollDelays)

	// Nothing outstanding: no poll.
	var pv permitView
	pv.armPlatePoll(0)
	if pv.PollNext != 0 || pv.PollDelay != 0 {
		t.Errorf("settled card armed a poll (PollNext=%d PollDelay=%d)", pv.PollNext, pv.PollDelay)
	}

	// A change in flight arms the next attempt, even from a full render (attempt 0)
	// with a fresh cache — the case the old staleness-only trigger missed — and does so
	// quickly, so a normal apply swaps in fast.
	pv = permitView{Applying: true}
	pv.armPlatePoll(0)
	if pv.PollNext != 1 || pv.PollDelay != platePollDelays[0] {
		t.Errorf("applying card armed %d/%ds, want 1/%ds", pv.PollNext, pv.PollDelay, platePollDelays[0])
	}
	if pv.PollDelay > 5 {
		t.Errorf("first poll delay %ds is too slow; a normal apply must swap in promptly", pv.PollDelay)
	}

	// A stale cache alone also arms it, with the backed-off delay for that attempt.
	pv = permitView{PlateRefreshing: true}
	pv.armPlatePoll(3)
	if pv.PollNext != 4 || pv.PollDelay != platePollDelays[3] {
		t.Errorf("refreshing card at attempt 3 armed %d/%ds, want 4/%ds", pv.PollNext, pv.PollDelay, platePollDelays[3])
	}

	// The count climbs with each served poll, right up to the last allowed one...
	pv = permitView{Applying: true}
	pv.armPlatePoll(cap - 1)
	if pv.PollNext != cap {
		t.Errorf("armed %d at the penultimate attempt, want %d", pv.PollNext, cap)
	}

	// ...and stops dead at the cap, however outstanding the change still is. This is
	// the bound that keeps an outage or a rejected change from looping forever — and it
	// marks the plate UNCONFIRMED so the pill shows an honest failure mark, not a
	// spinner frozen mid-check.
	pv = permitView{Applying: true, PlateRefreshing: true}
	pv.armPlatePoll(cap)
	if pv.PollNext != 0 || pv.PollDelay != 0 {
		t.Errorf("armed a poll at the cap (PollNext=%d PollDelay=%d) — an outage would loop", pv.PollNext, pv.PollDelay)
	}
	if !pv.PlateUnconfirmed {
		t.Error("capped card with an outstanding read/apply did not mark the plate unconfirmed — the pill would keep spinning")
	}

	// A SETTLED card at the cap (nothing outstanding) is NOT a failure: it shows the
	// tick, never the failure mark.
	pv = permitView{}
	pv.armPlatePoll(cap)
	if pv.PlateUnconfirmed {
		t.Error("a settled card was marked unconfirmed — it would show a failure mark instead of the tick")
	}

	// While still polling (under the cap), the card is not yet a failure.
	pv = permitView{PlateRefreshing: true}
	pv.armPlatePoll(2)
	if pv.PlateUnconfirmed {
		t.Error("a card still within its poll budget was marked unconfirmed")
	}
}

// TestPlatePollSurvivesSlowColdRead pins the reason the backoff exists: the poll must
// outlast a cold tenant read (an idle-day cache miss that silent-renews an expired
// token, then reads — each attempt up to ~25s, occasionally slow). The old flat 5s×10
// gave ~50s, which barely fitted two attempts; the window must now cover several
// minutes so a slow read lands instead of freezing the spinner.
func TestPlatePollSurvivesSlowColdRead(t *testing.T) {
	total := 0
	for _, d := range platePollDelays {
		if d <= 0 {
			t.Fatalf("a poll delay of %ds would busy-loop the client", d)
		}
		total += d
	}
	if total < 180 {
		t.Errorf("total poll window is only %ds; a cold read (multiple ~25s tries) needs a few minutes to land", total)
	}
	// Early polls stay quick (catch a normal apply, and a warm cold read that lands
	// in a couple of seconds — a flat 5s opener left the badge stale for the whole
	// 5s after the refresh had finished), later ones back off (don't hammer or
	// busy-poll during a long stall).
	if platePollDelays[0] > 2 {
		t.Errorf("first poll delay %ds is too slow: a warm cold read lands in ~2s and the badge should follow it", platePollDelays[0])
	}
	if platePollDelays[1] > 3 {
		t.Errorf("second poll delay %ds is too slow for a normal apply", platePollDelays[1])
	}
	if last := platePollDelays[len(platePollDelays)-1]; last < 30 {
		t.Errorf("tail poll delay %ds does not back off; a long stall would poll too eagerly", last)
	}
	// Non-decreasing: the cadence only ever slows, never speeds back up mid-stall.
	for i := 1; i < len(platePollDelays); i++ {
		if platePollDelays[i] < platePollDelays[i-1] {
			t.Errorf("delay decreased at index %d (%ds after %ds); backoff must be monotonic", i, platePollDelays[i], platePollDelays[i-1])
		}
	}
}
