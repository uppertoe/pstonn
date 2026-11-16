package notify

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/store"
)

// TestEnqueueApplyPerMemberPrefs is the regression test for the shared-account
// notification bug: a secondary turning their own email off must not silence the
// primary. EnqueueApply enqueues one outbox message per member, each honouring
// that member's own preference.
func TestEnqueueApplyPerMemberPrefs(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const primary, secondary = "primary@example.com", "member1@example.com"
	if err := st.AddMember(ctx, primary, secondary); err != nil {
		t.Fatal(err)
	}
	// Primary keeps email on; secondary turns their email off (and has no push), so
	// they want nothing. Quiet hours disabled (QuietFrom==QuietUntil==0) so the
	// enqueued item is due immediately and this fan-out test stays deterministic.
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: primary, EmailEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: secondary, EmailEnabled: false, NtfyEnabled: false}); err != nil {
		t.Fatal(err)
	}

	// A mailer that is "enabled" (Host+From) so EnqueueApply addresses email; it is
	// never drained here, so nothing is actually sent.
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("test-unsub-key"), nil) // no ntfy configured

	if err := svc.EnqueueApply(ctx, ApplyOutcome{Owner: primary, PermitLabel: "VPP1", Reg: "ABC123", OK: true}); err != nil {
		t.Fatal(err)
	}

	due, err := st.DueOutbox(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatal(err)
	}
	// Exactly one message, addressed to the primary only.
	if len(due) != 1 {
		t.Fatalf("outbox = %d messages, want 1 (primary only; secondary opted out)", len(due))
	}
	got := due[0]
	if len(got.Recipients) != 1 || got.Recipients[0] != primary {
		t.Fatalf("recipients = %v, want [%s] only", got.Recipients, primary)
	}
	for _, r := range got.Recipients {
		if r == secondary {
			t.Fatalf("secondary %s was emailed despite turning email off", secondary)
		}
	}

	// And the primary turning THEIR email off does not resurrect the secondary.
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: primary, EmailEnabled: true, NtfyEnabled: false}); err != nil {
		t.Fatal(err)
	}
	p, err := st.GetNotifyPref(ctx, primary)
	if err != nil || !p.EmailEnabled {
		t.Fatalf("primary pref should be independent and email-on: %+v (%v)", p, err)
	}
	sp, err := st.GetNotifyPref(ctx, secondary)
	if err != nil || sp.EmailEnabled {
		t.Fatalf("secondary pref should be independent and email-off: %+v (%v)", sp, err)
	}
}

// TestNotifyGuestRequestPerMemberFanout is the regression test for the
// approval-nudge channel gap: a push-only secondary used to get nothing (only
// the owner's ntfy topic was consulted). Every member must now be nudged on
// their own channels, quiet hours must not hold the nudge (someone is at the
// door), and one member's dedup must not swallow another member's row.
func TestNotifyGuestRequestPerMemberFanout(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const primary, secondary = "primary@example.com", "member1@example.com"
	if err := st.AddMember(ctx, primary, secondary); err != nil {
		t.Fatal(err)
	}
	// Primary: email only, with quiet hours spanning ALL day — which must be
	// ignored for a doorstep request. Secondary: push only, on their own topic.
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: primary, EmailEnabled: true, QuietFrom: 0, QuietUntil: 23}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: secondary, NtfyEnabled: true, NtfyTopic: "sec-topic"}); err != nil {
		t.Fatal(err)
	}

	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	svc := New(st, m, "https://ntfy.test", "", "", "", "", time.UTC, []byte("test-unsub-key"), nil)

	if err := svc.NotifyGuestRequest(ctx, primary, "VPP1", "TRD441", "https://p.example/guests", 41); err != nil {
		t.Fatal(err)
	}

	// Both rows must be due NOW (no quiet-hours deferral): one email row for the
	// primary, one ntfy row on the secondary's topic.
	due, err := st.DueOutbox(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 {
		t.Fatalf("outbox = %d due messages, want 2 (primary email + secondary push)", len(due))
	}
	var gotEmail, gotPush bool
	for _, it := range due {
		if len(it.Recipients) == 1 && it.Recipients[0] == primary && it.NtfyTopic == "" {
			gotEmail = true
		}
		if len(it.Recipients) == 0 && it.NtfyTopic == "sec-topic" {
			gotPush = true
		}
	}
	if !gotEmail || !gotPush {
		t.Fatalf("fanout rows wrong: email=%v push=%v (%+v)", gotEmail, gotPush, due)
	}

	// A re-scan of the same plate while the nudges are pending dedups silently —
	// nobody is notified twice.
	if err := svc.NotifyGuestRequest(ctx, primary, "VPP1", "TRD441", "", 41); err != nil {
		t.Fatal(err)
	}
	due, err = st.DueOutbox(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 {
		t.Fatalf("after re-scan outbox = %d, want still 2 (deduped)", len(due))
	}
}

// TestQueuedMailCarriesProvenance covers every path that puts person-facing mail
// in the OUTBOX rather than sending it immediately.
//
// sendEmail takes a reason parameter, so the compiler forces the direct senders
// to declare one — but the queued path carries the reason as a plain struct
// field, and four of the six enqueue sites simply omitted it. The mail those
// sites produce has no "you received this at X because Y" footer, which is the
// Spam Act s18 sender identification the compliance pass set out to add. Quiet
// hours default to 22:00-06:00, so the deferred path is the common one, not an
// edge case.
func TestQueuedMailCarriesProvenance(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const owner = "primary@example.com"
	// Put "now" inside quiet hours so every notification takes the DEFERRED branch
	// — the one that was dropping the reason. The window is anchored to the current
	// hour so this holds whenever the test runs (QuietUntil must be 0-23, so a
	// literal all-day window isn't expressible).
	nowHour := time.Now().In(time.UTC).Hour()
	if err := st.SetNotifyPref(ctx, store.NotifyPref{
		Owner: owner, EmailEnabled: true, QuietFrom: nowHour, QuietUntil: (nowHour + 2) % 24,
	}); err != nil {
		t.Fatal(err)
	}
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("test-unsub-key"), nil)

	cases := []struct {
		name string
		fire func() error
	}{
		{"apply outcome", func() error {
			return svc.EnqueueApply(ctx, ApplyOutcome{Owner: owner, PermitLabel: "VPP1", Reg: "ABC123", OK: true})
		}},
		{"permit expiry", func() error {
			svc.NotifyPermitExpiry(ctx, owner, "", "VPP1", time.Now().Add(14*24*time.Hour))
			return nil
		}},
		{"guest request", func() error {
			return svc.NotifyGuestRequest(ctx, owner, "VPP1", "XYZ789", "", 41)
		}},
	}
	for _, c := range cases {
		if err := c.fire(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
	}

	// Drain everything queued, however far in the future it was deferred.
	rows, err := st.DueOutbox(ctx, time.Now().UTC().Add(72*time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < len(cases) {
		t.Fatalf("queued %d messages, want at least %d — a path did not enqueue", len(rows), len(cases))
	}
	for _, r := range rows {
		if len(r.Recipients) == 0 {
			continue // push rows carry no footer
		}
		if r.Reason == "" {
			t.Errorf("queued mail to %v (subject %q) has no provenance reason: "+
				"it will send with no \"why you received this\" footer", r.Recipients, r.Subject)
		}
	}
}

// TestGuestRequestLinksToDecidePage: both channels lead straight to the
// member's no-sign-in decide page. The email links it as its only link (the
// signed-in Guests tab used to come first, and that was the one people tapped),
// and the push opens it on tap. The push body carries no URL itself: the
// capability rides the Click header, and the delivered row drops it.
func TestGuestRequestLinksToDecidePage(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const owner = "primary@example.com"
	// Both channels on for the same person, so each row is visible on one member.
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: true, NtfyEnabled: true, NtfyTopic: "own-topic"}); err != nil {
		t.Fatal(err)
	}
	var click string
	ntfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		click = r.Header.Get("Click")
	}))
	defer ntfy.Close()
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	svc := New(st, m, ntfy.URL, "", "https://p.example", "", "", time.UTC, nil, DeriveDecideKey(bytes.Repeat([]byte{7}, 32)))

	if err := svc.NotifyGuestRequest(ctx, owner, "VPP1", "TRD441", "https://p.example/guests", 41); err != nil {
		t.Fatal(err)
	}
	due, err := st.DueOutbox(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 {
		t.Fatalf("outbox = %d due messages, want 2 (email + push for the one member)", len(due))
	}
	for _, it := range due {
		if it.NtfyTopic == "" {
			if !strings.Contains(it.Body, "without signing in:\nhttps://p.example/r/41/") {
				t.Errorf("email body does not lead with the decide link:\n%s", it.Body)
			}
			if strings.Contains(it.Body, "/guests") || it.NtfyClick != "" {
				t.Errorf("email row carries the Guests tab or a tap target:\n%s (click %q)", it.Body, it.NtfyClick)
			}
			continue
		}
		if !strings.HasPrefix(it.NtfyClick, "https://p.example/r/41/") {
			t.Errorf("push tap target = %q, want the decide page", it.NtfyClick)
		}
		if strings.Contains(it.Body, "http") || !strings.Contains(it.Body, "Tap this notification") {
			t.Errorf("push body = %q, want the tap wording and no URL", it.Body)
		}
		svc.deliver(ctx, it)
		if click != it.NtfyClick {
			t.Errorf("delivered Click header = %q, want %q", click, it.NtfyClick)
		}
	}
}

// TestGuestRequestWithoutDecideKey: with no key to sign a decide link, both
// channels fall back to the Guests tab rather than a link that cannot work.
func TestGuestRequestWithoutDecideKey(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const owner = "primary@example.com"
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: true, NtfyEnabled: true, NtfyTopic: "own-topic"}); err != nil {
		t.Fatal(err)
	}
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	svc := New(st, m, "https://ntfy.test", "", "https://p.example", "", "", time.UTC, nil, nil)
	if err := svc.NotifyGuestRequest(ctx, owner, "VPP1", "TRD441", "https://p.example/guests", 41); err != nil {
		t.Fatal(err)
	}
	due, err := st.DueOutbox(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range due {
		if !strings.HasSuffix(it.Body, "https://p.example/guests") || strings.Contains(it.Body, "/r/") || it.NtfyClick != "" {
			t.Errorf("row (topic %q) = %q click %q, want the Guests-tab fallback", it.NtfyTopic, it.Body, it.NtfyClick)
		}
	}
}

// TestActionNeededFailureAlwaysEmails pins the safety rule: a member who turned
// email off (push-only, or nothing at all) is still emailed when an apply fails in
// a way that needs their hands — the fine-risk message must not ride a channel
// with no delivery receipt. Routine successes keep honouring the opt-out.
func TestActionNeededFailureAlwaysEmails(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const owner = "push-only@example.com"
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: false, NtfyEnabled: false}); err != nil {
		t.Fatal(err)
	}
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("test-unsub-key"), nil)

	// A success respects the opt-out: nothing is queued.
	if err := svc.EnqueueApply(ctx, ApplyOutcome{Owner: owner, PermitLabel: "VPP1", Reg: "ABC123", OK: true}); err != nil {
		t.Fatal(err)
	}
	if due, _ := st.DueOutbox(ctx, time.Now().UTC(), 10); len(due) != 0 {
		t.Fatalf("success with email off queued %d messages, want 0", len(due))
	}

	// A hard failure does not: the verified address is emailed anyway.
	if err := svc.EnqueueApply(ctx, ApplyOutcome{Owner: owner, PermitLabel: "VPP1", Reg: "ABC123", OK: false, Reason: "The council rejected the plate.", Action: "Set the vehicle yourself at the council."}); err != nil {
		t.Fatal(err)
	}
	due, err := st.DueOutbox(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || len(due[0].Recipients) != 1 || due[0].Recipients[0] != owner {
		t.Fatalf("action-needed failure with email off: outbox = %+v, want one message to %s", due, owner)
	}
}

// TestPermitExpiryAlwaysEmails: the expiry warning is safety-tier — a member with
// email off is still emailed. Quiet hours cover "now" so the notice takes the
// outbox path and the recipient list can be inspected.
func TestPermitExpiryAlwaysEmails(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const owner = "push-only@example.com"
	nowHour := time.Now().UTC().Hour()
	if err := st.SetNotifyPref(ctx, store.NotifyPref{
		Owner: owner, EmailEnabled: false, NtfyEnabled: false,
		QuietFrom: nowHour, QuietUntil: (nowHour + 2) % 24,
	}); err != nil {
		t.Fatal(err)
	}
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("test-unsub-key"), nil)

	if n := svc.NotifyPermitExpiry(ctx, owner, "", "VPP1", time.Now().Add(14*24*time.Hour)); n != 1 {
		t.Fatalf("delivered = %d, want 1 (queued email)", n)
	}
	rows, err := st.DueOutbox(ctx, time.Now().UTC().Add(3*time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(rows[0].Recipients) != 1 || rows[0].Recipients[0] != owner {
		t.Fatalf("expiry with email off: outbox = %+v, want one email to %s", rows, owner)
	}
}
