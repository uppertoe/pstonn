package mailer

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// The HTML wrapper carries the brand footer ("Not affiliated with…"), so its
// rendering is locked alongside the notify goldens. See internal/notify/golden_test.go.
//
//	go test ./internal/mailer -run Golden -update

var updateGolden = flag.Bool("update", false, "rewrite the golden file")

func TestGoldenHTMLDocument(t *testing.T) {
	body := "Hi,\r\n\r\nYour visitor permit is now set to ABC123 (Van).\r\n\r\nOpen p.stonn: https://p.stonn.org/schedule\r\n\r\n--\r\nYou received this at primary@example.com because you hold the permit.\r\nTo stop emails to primary@example.com: https://p.stonn.org/u/primary/TOKEN\r\n"
	got := []byte(htmlDocument("Visitor permit set to ABC123", body, "Not affiliated with the City of Stonnington.", "You received this at you@example.com because you hold the permit.", "https://p.stonn.org/u/addr/tok"))
	path := filepath.Join("testdata", "golden", "html-document.html")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no golden (run with -update): %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("html document differs from golden:\n--- want\n%s\n--- got\n%s", want, got)
	}
}
