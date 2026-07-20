package server

import (
	"testing"

	"github.com/uppertoe/pstonn/internal/config"
)

// TestHandlerRoutesNoConflict registers every route, so a Go 1.22 ServeMux
// pattern conflict (which panics at registration) is caught by unit tests, not
// only the CI boot smoke test. A minimal cfg lets Handler() finish past its
// post-registration middleware setup.
func TestHandlerRoutesNoConflict(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("route registration panicked (pattern conflict?): %v", r)
		}
	}()
	_ = (&Server{cfg: &config.Config{}}).Handler()
}
