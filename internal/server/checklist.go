package server

import (
	"context"

	"github.com/uppertoe/pstonn/internal/store"
)

// checklistView is the quiet per-tab card that shows what the tab can do, ticks
// each line as the household uses it, and goes away once everything is ticked.
// It replaces the explanatory strips: a line that ticks itself teaches the
// feature by showing it, where a sentence only describes it.
type checklistView struct {
	Key   string      // localStorage dismiss key suffix, one per tab
	Items []checkItem // in the order a household would naturally do them
	Done  int
}

type checkItem struct {
	Label string // the outcome, in the household's words
	Href  string // where it is done; "" once done
	Done  bool
}

// checklistFor builds the card for one tab from what the account has actually
// done. Every input is a count or a row the page already needs, so the card
// costs a few index reads. A tab whose lines are all ticked returns nil, and so
// does one with nothing to offer yet (no permit managed).
func (s *Server) checklistFor(ctx context.Context, owner, user, tab string) *checklistView {
	did := func(action string) bool {
		n, err := s.store.CountChanges(ctx, owner, action)
		return err == nil && n > 0
	}
	var items []checkItem
	switch tab {
	case "schedule":
		permits, _ := s.store.ListPermitsFor(ctx, owner)
		if len(permits) == 0 {
			return nil
		}
		roster, weeks := false, false
		for _, p := range permits {
			if rs, err := s.store.ListRules(ctx, p.ID); err == nil && len(rs) > 0 {
				roster = true
			}
			if p.CycleWeeks > 1 {
				weeks = true
			}
		}
		items = []checkItem{
			{Label: "Add a number plate to the weekly schedule", Href: "#roster", Done: roster},
			{Label: "Make a booking for a visitor who does not fit the roster", Href: "/schedule?book=1", Done: did(store.ActionOverrideAdd)},
		}
		if roster {
			items = append(items, checkItem{Label: "Add a second week, if the roster differs week to week", Href: "#roster", Done: weeks})
		}
	case "vehicles":
		vs, _ := s.store.ListVehiclesFor(ctx, owner)
		email := false
		for _, v := range vs {
			if v.Email != "" {
				email = true
			}
		}
		items = []checkItem{
			{Label: "Save the rego of someone who visits you", Href: "#add", Done: len(vs) > 0},
			{Label: "Add an email, so they are told when their rego goes on the permit", Href: "#add", Done: email},
		}
	case "guests":
		items = []checkItem{
			{Label: "Show a visitor QR to someone at the door", Href: "#now", Done: did(store.ActionDoorQRShow)},
			{Label: "Send a guest pass to a household that visits often", Href: "#new", Done: did(store.ActionGuestCreate)},
			{Label: "Print a QR that pings your phone when it is used", Href: "#now", Done: did(store.ActionDoorQRCreate)},
		}
	case "settings":
		permits, _ := s.store.ListPermitsFor(ctx, owner)
		named := false
		for _, p := range permits {
			if p.Label != "" && p.Label != p.PermitNumber {
				named = true
			}
		}
		household, _ := s.store.HouseholdName(ctx, owner)
		members, _ := s.store.CountMembers(ctx, owner)
		prefs, _ := s.store.HasNotifyPref(ctx, user)
		items = []checkItem{
			{Label: "Name the permit, as it appears on the schedule and in your emails", Href: "/schedule", Done: named},
			{Label: "Name the household, so visitors see it instead of your email", Href: "#household", Done: household != ""},
			{Label: "Give someone else in the house access", Href: "#shared", Done: members > 0},
			{Label: "Set how you want to be told about changes", Href: "#notifications", Done: prefs},
		}
	default:
		return nil
	}
	v := &checklistView{Key: tab, Items: items}
	for i := range items {
		if items[i].Done {
			v.Done++
			items[i].Href = ""
		}
	}
	if v.Done == len(items) {
		return nil
	}
	return v
}
