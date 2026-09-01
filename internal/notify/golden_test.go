package notify

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/tenant"
)

// Golden emails and pushes: the shape lock for every notice the app sends (see
// docs/council-connections.md and internal/server/golden_test.go for the pages).
// Each case drives one Service method against fixed fixtures and records what
// went out — direct emails (via the mailer hook), ntfy pushes (via a fake ntfy
// server) and outbox rows (drained after the call) — into one file under
// testdata/golden/. Signed URLs carry a wall-clock expiry, so their token segment
// is masked; everything else is compared byte-for-byte.
//
//	go test ./internal/notify -run Golden -update

var updateGolden = flag.Bool("update", false, "rewrite the golden files from the current output")

const (
	goldenDir = "testdata/golden"
	appURL    = "https://p.stonn.org"
	owner     = "primary@example.com"
	member    = "sam@example.com"
	stranger  = "guest@example.com"
)

// capture collects everything the service tried to send during one case.
type capture struct {
	mu  sync.Mutex
	buf bytes.Buffer
	// keys maps a stored (hashed) dedup key back to the plaintext the service
	// composed, recorded by the enqueue hook: the golden locks the composition,
	// which the digest the outbox now stores cannot show.
	keys map[string]string
}

func (c *capture) enqueued(it store.OutboxItem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys == nil {
		c.keys = map[string]string{}
	}
	c.keys[store.HashDedupKey(it.DedupKey)] = it.DedupKey
}

func (c *capture) email(to, subject, body string, o mailer.Options) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(&c.buf, "=== EMAIL to %s\nSubject: %s\n", to, subject)
	if o.ReplyTo != "" {
		fmt.Fprintf(&c.buf, "Reply-To: %s\n", o.ReplyTo)
	}
	if o.UnsubscribeURL != "" {
		fmt.Fprintf(&c.buf, "Unsubscribe: %s\n", o.UnsubscribeURL)
	}
	if o.Provenance != "" {
		fmt.Fprintf(&c.buf, "Provenance: %s\n", o.Provenance)
	}
	c.buf.WriteString("\n" + strings.ReplaceAll(body, "\r\n", "\n") + "\n\n")
	return nil
}

func (c *capture) ntfy(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(&c.buf, "=== NTFY %s\nTitle: %s\nPriority: %s\nTags: %s\n\n%s\n\n",
		strings.TrimPrefix(r.URL.Path, "/"), r.Header.Get("Title"), r.Header.Get("Priority"), r.Header.Get("Tags"), body)
	w.WriteHeader(http.StatusOK)
}

func (c *capture) outbox(it store.OutboxItem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := it.DedupKey
	if plain, ok := c.keys[key]; ok {
		key = plain
	}
	// The tier is only printed when set, so the routine goldens read as before
	// and a critical row stands out.
	tier := ""
	if it.Critical {
		tier = " critical=true"
	}
	fmt.Fprintf(&c.buf, "=== OUTBOX account=%s recipients=%s ntfy=%s/%s/%s reason=%s%s\nDedup: %s\nSubject: %s\n\n%s\n\n",
		it.Account, strings.Join(it.Recipients, ","), it.NtfyTopic, it.NtfyPriority, it.NtfyTag, it.Reason, tier, key, it.Subject,
		strings.ReplaceAll(it.Body, "\r\n", "\n"))
}

// Signed links: /u/<addr>/<token> and /r/<id>/<addr>/<token> embed an expiry.
var tokenRe = regexp.MustCompile(`(/u/[^/\s]+/|/r/[0-9]+/[^/\s]+/)[A-Za-z0-9_.-]+`)

func mask(s string) string { return tokenRe.ReplaceAllString(s, "${1}TOKEN") }

type rig struct {
	t   *testing.T
	ctx context.Context
	st  *store.Store
	svc *Service
	cap *capture
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c := &capture{}
	ntfy := httptest.NewServer(http.HandlerFunc(c.ntfy))
	t.Cleanup(ntfy.Close)
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	m.SetSendHook(c.email)
	loc, err := time.LoadLocation("Australia/Melbourne")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(st, m, ntfy.URL, "", appURL, "admin@stonn.org", "pstonn-admin", loc, []byte("golden-unsub-key"), []byte("golden-decide-key"))
	svc.enqueueHook = c.enqueued

	// Household: an owner with email + push, and a member with email only.
	if err := st.AddMember(ctx, owner, member); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: true, NtfyEnabled: true, NtfyTopic: "pstonn-primary"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: member, EmailEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPermit(ctx, owner, "14576", "14", "Visitor"); err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, ctx: ctx, st: st, svc: svc, cap: c}
}

// drain records and clears anything the call left in the outbox.
func (r *rig) drain() {
	r.t.Helper()
	due, err := r.st.DueOutbox(r.ctx, time.Now().Add(365*24*time.Hour), 100)
	if err != nil {
		r.t.Fatal(err)
	}
	for _, it := range due {
		r.cap.outbox(it)
		if err := r.st.MarkOutboxSent(r.ctx, it.ID); err != nil {
			r.t.Fatal(err)
		}
	}
}

func (r *rig) golden(name string) {
	r.t.Helper()
	r.drain()
	got := []byte(mask(r.cap.buf.String()))
	r.cap.buf.Reset()
	if len(got) == 0 {
		r.t.Errorf("%s: nothing was sent", name)
		return
	}
	path := filepath.Join(goldenDir, name+".txt")
	if *updateGolden {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			r.t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			r.t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		r.t.Errorf("no golden for %s (run with -update): %v", name, err)
		return
	}
	if !bytes.Equal(want, got) {
		r.t.Errorf("%s differs from its golden:\n--- want\n%s\n--- got\n%s", name, want, got)
	}
}

func TestGoldenEmails(t *testing.T) {
	r := newRig(t)
	ctx := r.ctx
	svc := r.svc
	at := time.Date(2026, time.August, 10, 14, 30, 0, 0, svc.loc)
	seen := map[string]bool{}
	run := func(name string, fn func()) {
		t.Helper()
		if seen[name] {
			t.Fatalf("duplicate case %s", name)
		}
		seen[name] = true
		fn()
		r.golden(name)
	}

	run("apply-success-roster", func() {
		_, _ = svc.NotifyApply(ctx, ApplyOutcome{Owner: owner, PermitLabel: "Visitor", Reg: "ABC123", Name: "Van", Source: "roster", OK: true})
	})
	run("apply-success-guest-displaced", func() {
		_, _ = svc.NotifyApply(ctx, ApplyOutcome{Owner: owner, PermitLabel: "Visitor", Reg: "GUEST1", By: "dad@example.com", Source: "guest", OK: true, DisplacedReg: "ABC123", DisplacedTold: true})
	})
	run("apply-failure-transient", func() {
		_, _ = svc.NotifyApply(ctx, ApplyOutcome{Owner: owner, PermitLabel: "Visitor", Reg: "ABC123", Name: "Van", Source: "roster", OK: false, CurrentReg: "XYZ789",
			Reason: "The council was temporarily unavailable.", Action: "Nothing to do yet — p.stonn keeps trying.", Transient: true})
	})
	run("apply-failure-urgent", func() {
		_, _ = svc.NotifyApply(ctx, ApplyOutcome{Owner: owner, PermitLabel: "Visitor", Reg: "ABC123", Name: "Van", Source: "override", OK: false, CurrentReg: "XYZ789",
			Reason: "The council rejected the change.", Action: "Check the permit on the council's site.", Urgent: true})
	})
	run("enqueue-apply", func() {
		_ = svc.EnqueueApply(ctx, ApplyOutcome{Owner: owner, PermitLabel: "Visitor", Reg: "ABC123", Name: "Van", Source: "roster", OK: true})
	})
	run("relink-required", func() { svc.NotifyRelinkRequired(ctx, owner, "") })
	run("reconnect-stalled", func() { svc.NotifyReconnectStalled(ctx, owner, "") })
	run("permit-expiry", func() { svc.NotifyPermitExpiry(ctx, owner, "", "Visitor", at.Add(14*24*time.Hour)) })
	run("renewal-reminder", func() {
		_ = svc.SendRenewalReminder(ctx, owner, "", at.Add(7*24*time.Hour), appURL+"/tenant/confirm?token=abc")
	})
	run("send-test", func() { _ = svc.SendTest(ctx, owner, "") })
	run("disconnected", func() { _ = svc.NotifyDisconnected(ctx, owner) })
	run("invite", func() { _ = svc.SendInvite(ctx, stranger, owner) })
	run("onboard-nudge", func() { _ = svc.SendOnboardNudge(ctx, stranger) })
	run("guest-link", func() { _ = svc.SendGuestLink(ctx, stranger, owner, "", "Visitor", appURL+"/g/tok") })
	run("driver-displaced", func() {
		_ = svc.NotifyDriverDisplaced(ctx, owner, stranger, "Visitor", "AAA111", "a one-off booking started", at)
	})
	run("driver-added", func() {
		_ = svc.NotifyDriverAdded(ctx, owner, "", stranger, "AAA111")
	})
	run("guest-request", func() { _ = svc.NotifyGuestRequest(ctx, owner, "Visitor", "GUEST1", appURL+"/g/req/4", 4) })
	run("account-change", func() { _ = svc.NotifyAccountChange(ctx, owner, member, "added the car ABC123 (Van)") })
	run("fortnight-nudge", func() { _ = svc.SendFortnightNudge(ctx, owner) })
	run("referral-invite", func() { _ = svc.SendReferralInvite(ctx, stranger, owner) })
	run("admin-alert", func() {
		_ = svc.NotifyAdmin(ctx, "Council may have renamed permit types", "Body line one.\nBody line two.")
	})

	// Every golden must belong to a case.
	entries, _ := os.ReadDir(goldenDir)
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".txt")
		if !seen[name] {
			t.Errorf("stale golden %s: no case produces it", e.Name())
		}
	}
}

// With a resolver that knows nothing about the account, wording and links fall
// back to the default tenant rather than failing or going blank.
func TestTenantOfUnknownAccountUsesDefault(t *testing.T) {
	svc := &Service{TenantFor: func(context.Context, string, string) *tenant.Tenant { return nil }}
	c := svc.tenantOf(context.Background(), "nobody@example.com", "")
	def := tenant.Default()
	if c.Name != def.Name || c.Links.Portal != def.Links.Portal || c.Terms["portal"] == "" {
		t.Fatalf("default council not applied: %+v", c)
	}
}
