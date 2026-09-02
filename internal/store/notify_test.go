package store

import (
	"context"
	"testing"
)

// TestFailureEpisodeRoundTrip: the episode records the plate told and the highest
// tier reached, never downgrades within a plate, follows a new plate, and clears.
func TestFailureEpisodeRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const pid = 7
	if p, u, err := st.FailureEpisode(ctx, pid); err != nil || p != "" || u {
		t.Fatalf("empty episode = (%q, %v, %v)", p, u, err)
	}
	if err := st.MarkFailureTold(ctx, pid, "ABC123", false); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkFailureTold(ctx, pid, "ABC123", true); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkFailureTold(ctx, pid, "ABC123", false); err != nil { // no downgrade
		t.Fatal(err)
	}
	if p, u, _ := st.FailureEpisode(ctx, pid); p != "ABC123" || !u {
		t.Fatalf("after soft, urgent, soft = (%q, %v), want (ABC123, true)", p, u)
	}
	if err := st.MarkFailureTold(ctx, pid, "NEW999", false); err != nil { // new plate resets the tier
		t.Fatal(err)
	}
	if p, u, _ := st.FailureEpisode(ctx, pid); p != "NEW999" || u {
		t.Fatalf("after a new plate = (%q, %v), want (NEW999, false)", p, u)
	}
	if err := st.CloseFailureEpisode(ctx, pid); err != nil {
		t.Fatal(err)
	}
	if p, u, _ := st.FailureEpisode(ctx, pid); p != "" || u {
		t.Fatalf("after close = (%q, %v), want empty", p, u)
	}
	// The other columns on the row are untouched by episode writes.
	if err := st.SetPermitNotifiedKey(ctx, pid, "success|A>B"); err != nil {
		t.Fatal(err)
	}
	_ = st.MarkFailureTold(ctx, pid, "ABC123", false)
	if k, _, _ := st.PermitNotify(ctx, pid); k != "success|A>B" {
		t.Fatalf("notified key clobbered by an episode write: %q", k)
	}
}
