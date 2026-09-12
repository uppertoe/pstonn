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
	Key   string // milestone key; recorded once the line is first seen done
	Label string // the outcome, in the household's words
	Href  string // where it is done; "" once done
	Done  bool
}

// checklistFor builds the card for one tab from what the account has actually
// done. Every input is a count or a row the page already needs, so the card
// costs a few index reads. A tab whose lines are all ticked returns nil, and so
// does one with nothing to offer yet (no permit managed).
// isPrimary drops the lines only the account owner can act on (naming the
// household, sharing access) for a member, who would otherwise be sent to a
// form they cannot see.
//
// Each line is satisfied by a durable milestone first (see store.MarkMilestone)
// and by current evidence second. The evidence tables are pruned at 90 days, so
// the first time evidence says "done" the milestone is written, and from then on
// the line stays ticked whatever the housekeeping removes.
func (s *Server) checklistFor(ctx context.Context, owner, user string, isPrimary bool, tab string) *checklistView {
	did := func(action string) bool {
		n, err := s.store.CountChanges(ctx, owner, action)
		return err == nil && n > 0
	}
	ms, _ := s.store.Milestones(ctx, owner)
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
			{Key: "roster", Label: "Add a number plate to the weekly schedule", Href: "#roster", Done: roster},
			{Key: "booking", Label: "Make a booking for a visitor who does not fit the roster", Href: "/schedule?book=1", Done: did(store.ActionOverrideAdd)},
		}
		if roster {
			items = append(items, checkItem{Key: "weeks", Label: "Add a second week, if the roster differs week to week", Href: "#roster", Done: weeks})
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
			{Key: "rego", Label: "Save the rego of someone who visits you", Href: "#add", Done: len(vs) > 0},
			{Key: "rego-email", Label: "Add an email, so they are told when their rego goes on the permit", Href: "#add", Done: email},
		}
	case "guests":
		// The grant rows outlive the change log (pruned at 90 days, and younger than
		// some accounts), so each line reads the durable row first and the log only
		// as a second opinion.
		passes, printed, shown, _ := s.store.GuestGrantKinds(ctx, owner)
		items = []checkItem{
			{Key: "visitor-qr", Label: "Show a visitor QR to someone at the door", Href: "#now", Done: shown > 0 || did(store.ActionDoorQRShow)},
			{Key: "guest-pass", Label: "Send a guest pass to a household that visits often", Href: "#new", Done: passes > 0 || did(store.ActionGuestCreate)},
			{Key: "printed-qr", Label: "Print a QR that pings your phone when it is used", Href: "#now", Done: printed > 0 || did(store.ActionDoorQRCreate)},
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
			{Key: "permit-name", Label: "Name the permit, as it appears on the schedule and in your emails", Href: "/schedule", Done: named},
		}
		if isPrimary {
			items = append(items,
				checkItem{Key: "household-name", Label: "Name the household, so visitors see it instead of your email", Href: "#household", Done: household != ""},
				checkItem{Key: "shared", Label: "Give someone else in the house access", Href: "#shared", Done: members > 0})
		}
		items = append(items, checkItem{Key: "notify:" + user, Label: "Set how you want to be told about changes", Href: "#notifications", Done: prefs})
	default:
		return nil
	}
	v := &checklistView{Key: tab, Items: items}
	for i := range items {
		if ms[items[i].Key] {
			items[i].Done = true
		} else if items[i].Done {
			// Evidence says done and no milestone yet: record it now, while the
			// evidence still exists.
			_ = s.store.MarkMilestone(ctx, owner, items[i].Key)
		}
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
