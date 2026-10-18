package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/mailer"
)

func received(t *testing.T, sesID, raw string, verdicts map[string]string) string {
	t.Helper()
	v := func(k string) map[string]string {
		s := verdicts[k]
		if s == "" {
			s = "PASS"
		}
		return map[string]string{"status": s}
	}
	ev := map[string]any{
		"notificationType": "Received",
		"mail": map[string]any{"messageId": sesID, "source": "bounce@sender.example",
			"commonHeaders": map[string]any{"from": []string{"Fallback <fallback@sender.example>"}, "subject": "Fallback subject"}},
		"receipt": map[string]any{"spamVerdict": v("spam"), "virusVerdict": v("virus"), "spfVerdict": v("spf"),
			"dkimVerdict": v("dkim"), "dmarcVerdict": v("dmarc"), "action": map[string]any{"type": "SNS", "encoding": "BASE64"}},
	}
	if raw != "" {
		ev["content"] = base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(raw, "\n", "\r\n")))
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mailboxServer(t *testing.T) (*Server, *[]mailer.Personal) {
	t.Helper()
	s := newAuthzServer(t)
	s.cfg = &config.Config{DisplayLocation: s.cfg.DisplayLocation, InboundTopicARN: "arn:aws:sns:ap-southeast-2:1:pstonn-inbound",
		MailboxFrom: "p.stonn <hello@stonn.org>", SMTP: config.SMTPConfig{Host: "smtp.example.com", Port: 587, From: "p.stonn <no-reply@stonn.org>"}}
	s.mail = mailer.New(s.cfg.SMTP)
	var sent []mailer.Personal
	s.mail.SetSendHook(func(to, subject, body string, o mailer.Options) error {
		sent = append(sent, mailer.Personal{To: to, Subject: subject, Body: body})
		return nil
	})
	return s, &sent
}

func TestInboundMailThreadsUnderTheNoteAndDedups(t *testing.T) {
	s, sent := mailboxServer(t)
	ctx := context.Background()
	const admin, origin = "ops@example.com", "http://app.example.com"
	// The operator writes a note…
	w := s.doAdmin(http.MethodPost, "/admin/mail/send", admin, origin, url.Values{
		"to": {"resident@example.com"}, "subject": {"p.stonn and your visitor permit"}, "body": {"Hello,\n\nWe noticed…"}})
	if w.Code != http.StatusSeeOther || len(*sent) != 1 || (*sent)[0].To != "resident@example.com" {
		t.Fatalf("send: code=%d sent=%+v body=%s", w.Code, *sent, w.Body.String())
	}
	threads, _ := s.store.MailThreads(ctx, 10)
	noteID := threads[0][0].MessageID
	// …and the resident's reply names it in In-Reply-To.
	raw := "From: Resident <Resident@Example.com>\nTo: hello@stonn.org\nSubject: Re: p.stonn and your visitor permit\n" +
		"Message-Id: <r1@example.com>\nIn-Reply-To: " + noteID + "\nReferences: " + noteID + "\n\nThank you, I just forgot.\n\nOn Sun, p.stonn wrote:\n> Hello,\n"
	for i := 0; i < 2; i++ { // the second is an SNS redelivery
		if err := s.handleInboundMail(ctx, received(t, "ses-1", raw, nil)); err != nil {
			t.Fatal(err)
		}
	}
	threads, _ = s.store.MailThreads(ctx, 10)
	if len(threads) != 1 || len(threads[0]) != 2 {
		t.Fatalf("want one thread of two messages, got %+v", threads)
	}
	in := threads[0][1]
	if !in.Inbound || in.FromAddr != "resident@example.com" || in.Flagged || !strings.HasPrefix(in.Body, "Thank you") {
		t.Fatalf("inbound row = %+v", in)
	}
	// The page shows the reply, folds the quote and offers an answer.
	w = s.doAdmin(http.MethodGet, "/admin/mail", admin, "", nil)
	body := w.Body.String()
	for _, want := range []string{"Thank you, I just forgot.", "Show the quoted message", `name="reply" value="` + id64(in.ID) + `"`, "waiting for an answer"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	// Answering threads the reply and addresses it to the sender, whatever the form says.
	w = s.doAdmin(http.MethodPost, "/admin/mail/send", admin, origin, url.Values{"reply": {id64(in.ID)}, "to": {"evil@example.net"}, "body": {"Glad to help."}})
	if w.Code != http.StatusSeeOther || (*sent)[1].To != "resident@example.com" || (*sent)[1].Subject != "Re: p.stonn and your visitor permit" {
		t.Fatalf("reply: code=%d sent=%+v", w.Code, (*sent)[1])
	}
	if n, _ := s.store.UnansweredMail(ctx); n != 0 {
		t.Errorf("unanswered = %d after the reply, want 0", n)
	}
}

func TestInboundMailFlagsAndOversize(t *testing.T) {
	s, _ := mailboxServer(t)
	ctx := context.Background()
	if err := s.handleInboundMail(ctx, received(t, "ses-spam", "From: x@spam.example\nSubject: offers\n\nbuy", map[string]string{"spam": "FAIL"})); err != nil {
		t.Fatal(err)
	}
	if err := s.handleInboundMail(ctx, received(t, "ses-big", "", nil)); err != nil {
		t.Fatal(err)
	}
	threads, _ := s.store.MailThreads(ctx, 10)
	if len(threads) != 2 {
		t.Fatalf("threads = %d", len(threads))
	}
	big, spam := threads[0][0], threads[1][0]
	if !spam.Flagged || !big.Truncated || big.FromAddr != "fallback@sender.example" || big.Subject != "Fallback subject" {
		t.Fatalf("spam=%+v big=%+v", spam, big)
	}
	if n, _ := s.store.UnansweredMail(ctx); n != 1 {
		t.Errorf("unanswered = %d, want 1 (the flagged one is not waiting)", n)
	}
}

func TestMailSendGuards(t *testing.T) {
	s, sent := mailboxServer(t)
	form := url.Values{"to": {"a@example.com"}, "subject": {"Hi"}, "body": {"Hello"}}
	// Cross-site: refused before anything is sent.
	if w := s.doAdmin(http.MethodPost, "/admin/mail/send", "ops@example.com", "", form); w.Code != http.StatusForbidden {
		t.Errorf("no origin: code=%d, want 403", w.Code)
	}
	// A signed-in non-admin: refused.
	if w := s.doReq(http.MethodPost, "/admin/mail/send", "user@example.com", "http://app.example.com", form); w.Code != http.StatusForbidden {
		t.Errorf("non-admin: code=%d, want 403", w.Code)
	}
	if len(*sent) != 0 {
		t.Fatalf("nothing should have been sent, got %+v", *sent)
	}
}

// doAdmin is doReq with the admin group.
func (s *Server) doAdmin(method, target, email, origin string, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, target, body)
	r.Host = "app.example.com"
	r.RemoteAddr = "10.0.0.2:41000"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.Header.Set("Remote-Email", email)
	r.Header.Set("Remote-Groups", "user,admin")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func id64(n int64) string { return strconv.FormatInt(n, 10) }

// TestHookRoutesInboundTopic drives the signed hook: a message on the inbound
// topic is stored as mail, the bounce topic still suppresses, and a third topic
// is refused.
func TestHookRoutesInboundTopic(t *testing.T) {
	s, key := newSESTestServer(t)
	s.cfg.InboundTopicARN = "arn:aws:sns:ap-southeast-2:1:pstonn-inbound"
	ts := func() string { return time.Now().UTC().Format(time.RFC3339) }
	raw := "From: someone@example.org\nSubject: Hello\nMessage-Id: <x1@example.org>\n\nHi there."
	body := signSNS(t, key, &snsMessage{Type: "Notification", MessageID: "i1", TopicARN: s.cfg.InboundTopicARN,
		Message: received(t, "ses-hook-1", raw, nil), Timestamp: ts()})
	if w := postSNS(s, body); w.Code != http.StatusOK {
		t.Fatalf("inbound = %d, want 200", w.Code)
	}
	threads, err := s.store.MailThreads(context.Background(), 10)
	if err != nil || len(threads) != 1 || threads[0][0].Body != "Hi there." {
		t.Fatalf("threads = %+v err=%v", threads, err)
	}
	body = signSNS(t, key, &snsMessage{Type: "Notification", MessageID: "i2", TopicARN: "arn:aws:sns:ap-southeast-2:1:other",
		Message: received(t, "ses-hook-2", raw, nil), Timestamp: ts()})
	if w := postSNS(s, body); w.Code != http.StatusForbidden {
		t.Fatalf("unknown topic = %d, want 403", w.Code)
	}
}
