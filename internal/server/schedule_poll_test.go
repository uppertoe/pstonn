package server

import "testing"

// armPlatePoll is the guard that lets a just-made change refresh into the card
// without letting a council outage poll forever. Both halves matter, so both are
// pinned here.
func TestArmPlatePoll(t *testing.T) {
	// Nothing outstanding: no poll.
	var pv permitView
	pv.armPlatePoll(0)
	if pv.PollNext != 0 {
		t.Errorf("settled card armed a poll (PollNext=%d)", pv.PollNext)
	}

	// A change in flight arms the next attempt, even from a full render (attempt 0)
	// with a fresh cache — the case the old staleness-only trigger missed.
	pv = permitView{Applying: true}
	pv.armPlatePoll(0)
	if pv.PollNext != 1 {
		t.Errorf("applying card did not arm attempt 1 (PollNext=%d)", pv.PollNext)
	}

	// A stale cache alone also arms it.
	pv = permitView{PlateRefreshing: true}
	pv.armPlatePoll(3)
	if pv.PollNext != 4 {
		t.Errorf("refreshing card at attempt 3 armed %d, want 4", pv.PollNext)
	}

	// The count climbs with each served poll, right up to the last allowed one...
	pv = permitView{Applying: true}
	pv.armPlatePoll(maxPlatePolls - 1)
	if pv.PollNext != maxPlatePolls {
		t.Errorf("armed %d at the penultimate attempt, want %d", pv.PollNext, maxPlatePolls)
	}

	// ...and stops dead at the cap, however outstanding the change still is. This is
	// the bound that keeps an outage or a rejected change from looping forever.
	pv = permitView{Applying: true, PlateRefreshing: true}
	pv.armPlatePoll(maxPlatePolls)
	if pv.PollNext != 0 {
		t.Errorf("armed a poll at the cap (PollNext=%d) — an outage would loop", pv.PollNext)
	}
}
