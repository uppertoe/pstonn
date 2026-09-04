package server

import (
	"github.com/uppertoe/pstonn/internal/redact"
	"log"
	"net/http"
)

// How many rows the Activity page shows. The question people actually arrive
// with is "did today's change go through?", and the answer to that is in the
// first few rows — so the default stays short enough that both logs fit in about
// a screen of phone scrolling rather than the 200 rows an uncapped page produced.
// "Show more" raises it to the retention ceiling; anything older is gone
// regardless (see PruneApplyLog / PruneChangeLog).
const (
	activityRows    = 10
	activityAllRows = 100
)

// activityPage shows what p.stonn did to the permit, and what people changed.
func (s *Server) activityPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "activity")
	if !ok {
		return
	}
	base.App = &appData{}
	limit := activityRows
	if r.URL.Query().Get("all") == "1" {
		limit = activityAllRows
	}
	base.App.ShowingAll = limit > activityRows

	// Ask for one more row than we display: getting it back is how we know there
	// is something older to offer, without a second COUNT query.
	logs, err := s.store.ListApplyLogFor(r.Context(), base.Owner, limit+1)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if len(logs) > limit {
		logs, base.App.LogMore = logs[:limit], true
	}
	base.App.Log = logs

	// Who changed the setup, alongside what p.stonn did to the permit. These are
	// different questions and the second one used to have no answer at all: a
	// configuration change produces no tenant apply, so it was invisible.
	changes, err := s.store.ListChanges(r.Context(), base.Owner, limit+1)
	if err != nil {
		// Best-effort: the apply log is the more important half, so don't fail the
		// page over the change log.
		log.Printf("activity: list changes for %s: %v", redact.Email(base.Owner), err)
	}
	if len(changes) > limit {
		changes, base.App.ChangesMore = changes[:limit], true
	}
	for _, c := range changes {
		base.App.Changes = append(base.App.Changes, changeView{
			Actor: c.Actor, Text: changeText(c), At: c.At,
		})
	}
	s.render(w, base)
}
