package inbound

import (
	"strings"
	"testing"
)

func crlf(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }

func TestParseIPhoneReply(t *testing.T) {
	raw := crlf(`From: =?UTF-8?Q?Ren=C3=A9e_Smith?= <Renee@Example.com>
To: p.stonn <hello@stonn.org>
Subject: Re: p.stonn and your visitor permit
Message-Id: <ABC-123@example.com>
In-Reply-To: <note-1@stonn.org>
References: <note-0@stonn.org> <note-1@stonn.org>
Content-Type: multipart/alternative; boundary="b1"
MIME-Version: 1.0

--b1
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Thanks =E2=80=94 I just forgot it was there.

On 18 Oct 2026, at 9:17=E2=80=AFam, p.stonn <hello@stonn.org> wrote:

> Hello,
--b1
Content-Type: text/html; charset=utf-8

<p>Thanks</p>
--b1--
`)
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.FromAddr != "renee@example.com" || m.FromName != "Renée Smith" {
		t.Errorf("from = %q %q", m.FromAddr, m.FromName)
	}
	if m.MessageID != "<ABC-123@example.com>" || m.InReplyTo != "<note-1@stonn.org>" || len(m.References) != 2 {
		t.Errorf("ids = %q %q %v", m.MessageID, m.InReplyTo, m.References)
	}
	if !strings.HasPrefix(m.Text, "Thanks — I just forgot") {
		t.Errorf("text = %q", m.Text)
	}
	reply, quoted := SplitQuoted(m.Text)
	if reply != "Thanks — I just forgot it was there." || !strings.HasPrefix(quoted, "On 18 Oct") {
		t.Errorf("split = %q / %q", reply, quoted)
	}
	if m.AutoSubmitted {
		t.Error("a person's reply is not auto-submitted")
	}
}

func TestParseHTMLOnlyBase64AndAttachment(t *testing.T) {
	raw := crlf(`From: someone@example.org
Subject: Hello
Auto-Submitted: auto-replied
Content-Type: multipart/mixed; boundary="m"

--m
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: base64

PHN0eWxlPnB7fTwvc3R5bGU+PHA+T25lICZhbXA7IHR3bzwvcD48cD5UaHJlZTwvcD4=
--m
Content-Type: text/plain
Content-Disposition: attachment; filename="x.txt"

not this
--m--
`)
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Text != "One & two\nThree" {
		t.Errorf("text = %q", m.Text)
	}
	if !m.AutoSubmitted {
		t.Error("Auto-Submitted: auto-replied must be flagged")
	}
}

func TestParseLatin1AndClip(t *testing.T) {
	body := strings.Repeat("é", MaxBody) // two bytes each once decoded
	raw := append(crlf("From: a@b.c\nContent-Type: text/plain; charset=iso-8859-1\n\n"), []byte(strings.Repeat("\xe9", MaxBody))...)
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Truncated || len(m.Text) > MaxBody || !strings.HasPrefix(body, m.Text) {
		t.Errorf("truncated=%v len=%d", m.Truncated, len(m.Text))
	}
}

func TestSplitQuotedNoQuote(t *testing.T) {
	if r, q := SplitQuoted("Just this."); r != "Just this." || q != "" {
		t.Errorf("%q %q", r, q)
	}
	if r, q := SplitQuoted("Yes please.\n\n> Hello"); r != "Yes please." || q != "> Hello" {
		t.Errorf("%q %q", r, q)
	}
}
