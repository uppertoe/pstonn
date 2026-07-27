package server

import (
	"log"
	"net/http"
)

// activityPage shows the recent-changes log.
func (s *Server) activityPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "activity")
	if !ok {
		return
	}
	logs, err := s.store.ListApplyLogFor(r.Context(), base.Owner, 100)
	if err != nil {
		s.serverError(w, err)
		return
	}
	base.Log = logs
	// Who changed the setup, alongside what p.stonn did to the permit. These are
	// different questions and the second one used to have no answer at all: a
	// configuration change produces no council apply, so it was invisible.
	changes, err := s.store.ListChanges(r.Context(), base.Owner, 100)
	if err != nil {
		// Best-effort: the apply log is the more important half, so don't fail the
		// page over the change log.
		log.Printf("activity: list changes for %s: %v", base.Owner, err)
	}
	for _, c := range changes {
		base.Changes = append(base.Changes, changeView{
			Actor: c.Actor, Text: changeText(c), At: c.At,
		})
	}
	s.render(w, base)
}
