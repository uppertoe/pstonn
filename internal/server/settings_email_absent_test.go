package server

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/store"
)

// TestSettingsSaveWithoutEmailChannel: on a deployment with no mailer the email
// checkbox is not rendered, so every save arrives with email off — and the
// "confirm push before turning email off" guard read that as an attempt to turn
// email off, refusing every save (quiet hours, failures-only, all of it) until a
// push had been confirmed. The guard applies only where email is on offer.
func TestSettingsSaveWithoutEmailChannel(t *testing.T) {
	s, _, user := newNtfyServer(t)
	// Same push server, no mailer.
	s.notify = notify.New(s.store, nil, s.notify.NtfyBase(), "", "https://app.example.com", "", "", time.UTC, nil,
		notify.DeriveDecideKey(bytes.Repeat([]byte{7}, 32)))
	if s.notify.EmailAvailable() {
		t.Fatal("fixture: email must be unavailable for this case")
	}
	ctx := context.Background()
	if err := s.store.SetNotifyPref(ctx, store.NotifyPref{Owner: user, NtfyEnabled: true, NtfyTopic: notify.RandomTopic()}); err != nil {
		t.Fatal(err)
	}
	w := s.doHX("POST", "/notifications", user, "http://app.example.com", url.Values{"ntfy_enabled": {"1"}, "failures_only": {"1"}})
	// The refusal is the "⚠ …" status line; the bare phrase also lives in the
	// fragment's client-side guard, so it is not the thing to look for.
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "⚠ You can turn off email") {
		t.Fatalf("push-only save with no email channel: code=%d body=%s", w.Code, excerpt(w.Body.String()))
	}
	if p := s.prefOf(t, user); !p.FailuresOnly || !p.NtfyEnabled {
		t.Fatalf("save refused: %+v", p)
	}
}

// TestNtfyConfirmedOnUsesAccountZone: the "confirmed on" day was formatted in the
// process zone (UTC in the container), unlike every other date on Settings. Pinned
// with a zone that is neither UTC nor the developer's, so the wrong clock cannot
// pass by coincidence.
func TestNtfyConfirmedOnUsesAccountZone(t *testing.T) {
	s := newAuthzServer(t)
	la, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Skip("zoneinfo unavailable")
	}
	s.cfg.DisplayLocation = la
	s.notify = notify.New(s.store, nil, "", "", "https://app.example.com", "", "", time.UTC, nil, nil)
	// 05:30 UTC on the 11th is still the evening of the 10th in Los Angeles.
	nv := s.notifyViewOf(context.Background(), "u@example.com", store.NotifyPref{NtfyConfirmedAt: "2026-08-11T05:30:00Z"})
	if nv.NtfyConfirmedOn != "10 Aug 2026" {
		t.Fatalf("NtfyConfirmedOn = %q, want \"10 Aug 2026\" in the account's zone", nv.NtfyConfirmedOn)
	}
}
