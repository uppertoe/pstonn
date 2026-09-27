package server

import (
	"net/http/httptest"
	"testing"

	"github.com/uppertoe/pstonn/internal/store"
)

// The guest page's view log names the pass by kind and the viewer by a coarse
// class, so a person's phone reads differently from the preview fetchers and
// mail scanners that also open emailed links.
func TestGuestViewLogClasses(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 Version/26.0 Mobile/15E148 Safari/604.1", "iPhone"},
		{"Mozilla/5.0 (Linux; Android 16; SM-S928B) AppleWebKit/537.36 Chrome/140.0 Mobile Safari/537.36", "Android"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.4 Safari/601.2.4 facebookexternalhit/1.1 Facebot Twitterbot/1.0", "bot or link preview"},
		{"NetworkingExtension/8624.5.1.10.3 Network/5812.160.9 iOS/26.6.2", "bot or link preview"},
		{"WhatsApp/2.24.20.0 i", "bot or link preview"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36", "Windows"},
		{"", "no user agent"},
	} {
		r := httptest.NewRequest("GET", "/g/x", nil)
		r.Header.Set("User-Agent", c.ua)
		if got := guestViewer(r); got != c.want {
			t.Errorf("guestViewer(%q) = %q, want %q", c.ua, got, c.want)
		}
	}
	for _, c := range []struct {
		g    store.GuestGrant
		want string
	}{
		{store.GuestGrant{Picker: true}, "quick picker"},
		{store.GuestGrant{RequestOnly: true}, "printed QR"},
		{store.GuestGrant{}, "pass"},
	} {
		if got := guestKind(c.g); got != c.want {
			t.Errorf("guestKind(%+v) = %q, want %q", c.g, got, c.want)
		}
	}
}
