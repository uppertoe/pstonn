package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uppertoe/pstonn/internal/identity"
)

// TestShareShellResolvesTheHousehold: the Share page built its own base view and
// took resolveAccount's FIRST result (the signed-in address) as Owner, so a
// secondary's page was scoped to themselves rather than the household. The shell
// must resolve the way appShell does: Owner is the account, the role is kept, and
// the nav gets its shared-with line.
func TestShareShellResolvesTheHousehold(t *testing.T) {
	s := newAuthzServer(t)
	ctx := context.Background()
	const owner, secondary = "primary@example.com", "helper@example.com"
	if err := s.store.AddMember(ctx, owner, secondary); err != nil {
		t.Fatal(err)
	}
	var got dashboardData
	h := identityMiddlewareFor(s)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := identity.FromContext(r.Context())
		got = s.shareShell(r.Context(), u)
	}))
	r := httptest.NewRequest("GET", "/share", nil)
	r.RemoteAddr = "10.0.0.2:41000"
	r.Header.Set("Remote-Email", secondary)
	r.Header.Set("Remote-Groups", "user")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if got.User.Email != secondary {
		t.Fatalf("User = %q, want the signed-in %q", got.User.Email, secondary)
	}
	if got.Owner != owner || got.IsPrimary {
		t.Fatalf("Owner=%q IsPrimary=%v, want the household %q as a secondary", got.Owner, got.IsPrimary, owner)
	}
	if got.SharedWith != owner {
		t.Fatalf("SharedWith = %q, want %q like appShell", got.SharedWith, owner)
	}
}
