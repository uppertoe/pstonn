package server

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/store"
)

// captureLog redirects the default slog logger (which applog logs through) for
// the duration of fn.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{})))
	defer slog.SetDefault(old)
	fn()
	return buf.String()
}

// acceptTermsForm builds a POST body with every clause ticked.
func acceptTermsForm(s *Server) url.Values {
	f := url.Values{}
	for i := range s.terms.Clauses {
		f.Set(fmt.Sprintf("agree%d", i), "on")
	}
	return f
}

// The sign-up funnel milestone: the FIRST time an email accepts the terms logs
// a redacted "new account" line; a re-acceptance (a terms-change day, when
// everyone re-consents) does NOT, so the log is not flooded. Drives the real
// acceptTerms handler over HTTP.
func TestNewAccountMilestoneLogsOnceRedacted(t *testing.T) {
	s := newAuthzServer(t)
	const owner = "signup@example.com"
	form := acceptTermsForm(s)

	out := captureLog(t, func() {
		rec := s.doReq(http.MethodPost, "/terms/accept", owner, "https://app.example.com", form)
		if rec.Code >= 400 {
			t.Fatalf("first accept: HTTP %d", rec.Code)
		}
	})
	if !strings.Contains(out, "new account for s***@example.com") {
		t.Fatalf("first consent should log a redacted new-account milestone; got: %q", out)
	}
	if strings.Contains(out, owner) {
		t.Fatalf("milestone leaked the full address: %q", out)
	}

	out = captureLog(t, func() {
		rec := s.doReq(http.MethodPost, "/terms/accept", owner, "https://app.example.com", form)
		if rec.Code >= 400 {
			t.Fatalf("second accept: HTTP %d", rec.Code)
		}
	})
	if strings.Contains(out, "new account") {
		t.Fatalf("a re-acceptance must not log a new-account milestone; got: %q", out)
	}
}

// Guard the action constants the link/unlink milestones sit beside, so a rename
// can't silently drop them.
func TestMilestoneActionConstantsExist(t *testing.T) {
	if store.ActionCouncilLink == "" || store.ActionCouncilUnlink == "" {
		t.Fatal("council link/unlink action constants must be non-empty")
	}
}
