package server

import (
	"context"

	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/store"
)

// checklistView is the quiet per-tab card that shows what the tab can do, ticks
// each line as the household uses it, and goes away once everything is ticked.
// It replaces explanatory strips: a line that ticks itself teaches the feature
// by showing it, where a sentence only describes it.
type checklistView struct {
	Key   string      // localStorage key suffix, one per tab
	Items []checkItem // in the order a household would naturally do them
	Done  int
}

type checkItem struct {
	Milestone store.Milestone
	Label     string // the outcome, in the household's words
	Href      string // where it is done; "" once done
	Done      bool
}

// checklistFor builds the card for one tab.
//
// A line is satisfied by its milestone, which the successful action records
// (see logChange and milestoneForChange). Current state is consulted only as a
// healing path for accounts that did things before milestones existed: when it
// shows a line done and no milestone is recorded, the milestone is written
// then, while the evidence still exists. That path can go once every old
// account has been visited; nothing new should rely on it.
//
// Any read failing makes the card unavailable rather than wrong: "unknown" is
// not "not done", and telling a household to try what it has done is worse
// than a missing card. One warning covers the whole render.
func (s *Server) checklistFor(ctx context.Context, owner, user string, isPrimary bool, tab string) *checklistView {
	var readErr error
	note := func(err error) {
		if err != nil && readErr == nil {
			readErr = err
		}
	}
	did := func(action string) bool {
		n, err := s.store.CountChanges(ctx, owner, action)
		note(err)
		return err == nil && n > 0
	}
	ms, err := s.store.Milestones(ctx, owner)
	note(err)

	var items []checkItem
	switch tab {
	case "schedule":
		permits, err := s.store.ListPermitsFor(ctx, owner)
		note(err)
		if len(permits) == 0 {
			return nil
		}
		roster, weeks := false, false
		for _, p := range permits {
			rs, err := s.store.ListRules(ctx, p.ID)
			note(err)
			if len(rs) > 0 {
				roster = true
			}
			if p.CycleWeeks > 1 {
				weeks = true
			}
		}
		items = []checkItem{
			{Milestone: store.MilestoneRoster, Label: "Add a number plate to the weekly schedule", Href: "#roster", Done: roster},
			{Milestone: store.MilestoneBooking, Label: "Make a booking for a visitor who does not fit the roster", Href: "/schedule?book=1", Done: did(store.ActionOverrideAdd)},
		}
		if roster || ms[store.MilestoneRoster] {
			items = append(items, checkItem{Milestone: store.MilestoneWeeks, Label: "Add a second week, if the roster differs week to week", Href: "#roster", Done: weeks})
		}
	case "vehicles":
		vs, err := s.store.ListVehiclesFor(ctx, owner)
		note(err)
		email := false
		for _, v := range vs {
			if v.Email != "" {
				email = true
			}
		}
		items = []checkItem{
			{Milestone: store.MilestoneRego, Label: "Save the rego of someone who visits you", Href: "#add", Done: len(vs) > 0},
			{Milestone: store.MilestoneRegoEmail, Label: "Add an email, so they are told when their rego goes on the permit", Href: "#add", Done: email},
		}
	case "guests":
		passes, printed, shown, err := s.store.GuestGrantKinds(ctx, owner)
		note(err)
		items = []checkItem{
			{Milestone: store.MilestoneVisitorQR, Label: "Show a visitor QR to someone at the door", Href: "#now", Done: shown > 0 || did(store.ActionDoorQRShow)},
			{Milestone: store.MilestoneGuestPass, Label: "Send a guest pass to a household that visits often", Href: "#new", Done: passes > 0 || did(store.ActionGuestCreate)},
			{Milestone: store.MilestonePrintedQR, Label: "Print a QR that pings your phone when it is used", Href: "#now", Done: printed > 0 || did(store.ActionDoorQRCreate)},
		}
	case "settings":
		permits, err := s.store.ListPermitsFor(ctx, owner)
		note(err)
		named := false
		for _, p := range permits {
			if p.Label != "" && p.Label != p.PermitNumber {
				named = true
			}
		}
		prefs, err := s.store.HasNotifyPref(ctx, user)
		note(err)
		items = []checkItem{
			{Milestone: store.MilestonePermitName, Label: "Name the permit, as it appears on the schedule and in your emails", Href: "/schedule", Done: named},
		}
		if isPrimary {
			household, err := s.store.HouseholdName(ctx, owner)
			note(err)
			members, err := s.store.CountMembers(ctx, owner)
			note(err)
			items = append(items,
				checkItem{Milestone: store.MilestoneHouseholdName, Label: "Name the household, so visitors see it instead of your email", Href: "#household", Done: household != ""},
				checkItem{Milestone: store.MilestoneShared, Label: "Give someone else in the house access", Href: "#shared", Done: members > 0})
		}
		items = append(items, checkItem{Milestone: store.MilestoneNotify(user), Label: "Set how you want to be told about changes", Href: "#notifications", Done: prefs})
	default:
		return nil
	}
	if readErr != nil {
		alog.Warnf("checklist for %s (%s) unavailable: %v", redact.Email(owner), tab, readErr)
		return nil
	}
	v := &checklistView{Key: tab, Items: items}
	for i := range items {
		if ms[items[i].Milestone] {
			items[i].Done = true
		} else if items[i].Done {
			// Healing: the account did this before milestones were recorded.
			if err := s.store.MarkMilestone(ctx, owner, items[i].Milestone); err != nil {
				alog.Infof("milestone backfill %s %s: %v", items[i].Milestone, redact.Email(owner), err)
			}
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
