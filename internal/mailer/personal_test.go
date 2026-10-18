package mailer

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSMTP accepts one message and reports its MAIL FROM line and its data.
func fakeSMTP(t *testing.T) (addr string, got chan [2]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan [2]string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		write("220 test ESMTP")
		var from string
		var data strings.Builder
		inData := false
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if strings.TrimRight(line, "\r\n") == "." {
					write("250 OK")
					got <- [2]string{from, data.String()}
					inData = false
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"):
				write("250 test")
			case strings.HasPrefix(cmd, "MAIL"):
				from = strings.TrimSpace(line)
				write("250 OK")
			case strings.HasPrefix(cmd, "DATA"):
				write("354 send it")
				inData = true
			case strings.HasPrefix(cmd, "QUIT"):
				write("221 bye")
				return
			default:
				write("250 OK")
			}
		}
	}()
	return ln.Addr().String(), got
}

func TestSendPersonal(t *testing.T) {
	addr, got := fakeSMTP(t)
	m := &Mailer{host: "127.0.0.1", addr: addr, from: "p.stonn <no-reply@stonn.org>"}
	id, err := m.SendPersonal(Personal{
		From: "p.stonn <hello@stonn.org>", To: "someone@example.com", Subject: "Re: Your permit",
		Body: "Hello,\n\nThank you.", InReplyTo: "<r1@example.com>", References: []string{"<n1@stonn.org>", "<r1@example.com>"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(id, "@stonn.org>") {
		t.Errorf("message id %q should carry the sender's domain", id)
	}
	select {
	case g := <-got:
		if !strings.Contains(g[0], "<hello@stonn.org>") {
			t.Errorf("envelope sender = %q, want hello@stonn.org", g[0])
		}
		msg := g[1]
		for _, want := range []string{"From: p.stonn <hello@stonn.org>", "Message-ID: " + id, "In-Reply-To: <r1@example.com>",
			"References: <n1@stonn.org> <r1@example.com>", "Content-Type: text/plain; charset=UTF-8"} {
			if !strings.Contains(msg, want) {
				t.Errorf("missing %q", want)
			}
		}
		for _, banned := range []string{"Auto-Submitted", "List-Unsubscribe", "multipart"} {
			if strings.Contains(msg, banned) {
				t.Errorf("a personal message must not carry %q", banned)
			}
		}
		if !strings.Contains(decodeAnyBase64(msg), "Thank you.") {
			t.Error("body missing")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no message received")
	}
}
