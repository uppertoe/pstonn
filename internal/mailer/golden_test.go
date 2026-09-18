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
	checkGolden(t, "html-document.html", htmlDocument("Visitor permit set to ABC123", body, "Not affiliated with the City of Stonnington.", "You received this at you@example.com because you hold the permit.", "https://p.stonn.org/u/addr/tok", Hero{Plate: "ABC123", Color: "#3b82f6"}))
}

// The displaced-driver notice leads with the plate that came OFF, so its chip
// carries a caption; the neutral chip (no colour) is locked here too.
func TestGoldenHTMLDocumentCaptionedHero(t *testing.T) {
	body := "Your rego AAA111 came off the visitor parking permit for Visitor at 2:30pm: a one-off booking started.\r\n\r\nIf your car is still parked there it's no longer covered.\r\n"
	checkGolden(t, "html-document-captioned.html", htmlDocument("Heads up: AAA111 is no longer covered on the visitor permit", body, "Not affiliated with the City of Stonnington.", "", "https://p.stonn.org/u/addr/tok", Hero{Plate: "AAA111", Caption: "No longer on the permit"}))
}

func checkGolden(t *testing.T, name, rendered string) {
	t.Helper()
	got := []byte(rendered)
	path := filepath.Join("testdata", "golden", name)
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
