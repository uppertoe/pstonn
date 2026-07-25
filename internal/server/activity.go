package server

import (
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
	s.render(w, base)
}
