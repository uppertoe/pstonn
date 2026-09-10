package notify

import (
	"strings"
	"testing"
)

func TestContactPreview(t *testing.T) {
	if got := contactPreview("  hello\n\n   world  "); got != "hello world" {
		t.Fatalf("whitespace not collapsed: %q", got)
	}
	long := strings.Repeat("é", contactPreviewRunes+50)
	got := contactPreview(long)
	if r := []rune(got); len(r) != contactPreviewRunes+1 || !strings.HasSuffix(got, "…") {
		t.Fatalf("preview not trimmed to %d runes + ellipsis: %d", contactPreviewRunes, len(r))
	}
}
