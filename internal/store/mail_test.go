package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMailThreading(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	// A note we sent starts its own thread.
	noteID, noteThread, err := st.AddMail(ctx, MailMessage{ToAddr: "a@example.com", Subject: "Note", MessageID: "<n1@stonn.org>"}, "")
	if err != nil || noteThread != noteID {
		t.Fatalf("note: id=%d thread=%d err=%v", noteID, noteThread, err)
	}
	// The reply names it in In-Reply-To and joins that thread.
	_, th, err := st.AddMail(ctx, MailMessage{Inbound: true, SESMessageID: "ses-1", FromAddr: "a@example.com",
		MessageID: "<r1@example.com>", References: []string{"<n1@stonn.org>"}}, "<n1@stonn.org>")
	if err != nil || th != noteThread {
		t.Fatalf("reply: thread=%d want %d err=%v", th, noteThread, err)
	}
	// An SNS redelivery of the same SES message is refused.
	if _, _, err := st.AddMail(ctx, MailMessage{Inbound: true, SESMessageID: "ses-1"}, ""); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("redelivery: err=%v, want ErrDuplicate", err)
	}
	// A stranger's message starts a new thread, newest first in the list.
	_, other, err := st.AddMail(ctx, MailMessage{Inbound: true, SESMessageID: "ses-2", FromAddr: "b@example.com"}, "<unknown@x>")
	if err != nil || other == noteThread {
		t.Fatalf("stranger: thread=%d err=%v", other, err)
	}
	threads, err := st.MailThreads(ctx, 10)
	if err != nil || len(threads) != 2 || threads[0][0].ThreadID != other || len(threads[1]) != 2 || !threads[1][1].Inbound {
		t.Fatalf("threads = %+v err=%v", threads, err)
	}
	if n, err := st.UnansweredMail(ctx); err != nil || n != 2 {
		t.Fatalf("unanswered = %d err=%v, want 2", n, err)
	}
	if n, err := st.PruneMail(ctx, time.Now().Add(time.Hour)); err != nil || n != 3 {
		t.Fatalf("prune = %d err=%v", n, err)
	}
}
