package server

import (
	"log"
	"net/http"
)

// How many rows the Activity page shows. The question people actually arrive
// with is "did today's change go through?", so a short list answers it without a
// wall of scrolling on a phone — and a full-size list of BOTH logs was 200 rows.
// "Show everything" raises it to the retention ceiling; anything older is gone
// regardless (see PruneApplyLog / PruneChangeLog).
const (
	activityRows    = 20
	activityAllRows = 100
)

// activityPage shows what p.stonn did to the permit, and what people changed.
func (s *Server) activityPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "activity")
	if !ok {
		return
	}
	limit := activityRows
	if r.URL.Query().Get("all") == "1" {
		limit = activityAllRows
	}
	base.ShowingAll = limit > activityRows

	// Ask for one more row than we display: getting it back is how we know there
	// is something older to offer, without a second COUNT query.
	logs, err := s.store.ListApplyLogFor(r.Context(), base.Owner, limit+1)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if len(logs) > limit {
		logs, base.LogMore = logs[:limit], true
	}
	base.Log = logs

	// Who changed the setup, alongside what p.stonn did to the permit. These are
	// different questions and the second one used to have no answer at all: a
	// configuration change produces no council apply, so it was invisible.
	changes, err := s.store.ListChanges(r.Context(), base.Owner, limit+1)
	if err != nil {
		// Best-effort: the apply log is the more important half, so don't fail the
		// page over the change log.
		log.Printf("activity: list changes for %s: %v", base.Owner, err)
	}
	if len(changes) > limit {
		changes, base.ChangesMore = changes[:limit], true
	}
	for _, c := range changes {
		base.Changes = append(base.Changes, changeView{
			Actor: c.Actor, Text: changeText(c), At: c.At,
		})
	}
	s.render(w, base)
}
