package server

import (
	"fmt"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
)

// TestNewInitialisesEveryRateLimiter walks the Server struct and fails on any
// *rateLimiter field New left nil.
//
// This exists because statusLimit shipped declared and CHECKED but never
// constructed, so the throttle on the roster endpoint silently did nothing: a
// nil limiter's allow() returns true, and every test builds Server as a struct
// literal, so nothing noticed. A per-field assertion would have the same blind
// spot the next time a limiter is added — reflection is what makes this hold for
// limiters that do not exist yet.
func TestNewInitialisesEveryRateLimiter(t *testing.T) {
	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil, nil)

	v := reflect.ValueOf(s).Elem()
	limiterType := reflect.TypeOf((*rateLimiter)(nil))
	checked := 0
	for i := 0; i < v.NumField(); i++ {
		if v.Type().Field(i).Type != limiterType {
			continue
		}
		checked++
		if v.Field(i).IsNil() {
			t.Errorf("New() left %s nil: the throttle it guards does nothing, because allow() on a nil limiter permits everything", v.Type().Field(i).Name)
		}
	}
	if checked == 0 {
		t.Fatal("no *rateLimiter fields found — this test is no longer checking anything")
	}
}

// TestRateLimiterKeyCapKeepsBlockedKeys: overflowing the key cap must not hand a
// blocked key a free pass.
//
// Rotating source addresses is cheap (an IPv6 /64 is effectively unlimited), so
// if overflow cleared the whole map an attacker could keep it saturated and
// thereby keep resetting every real limiter — including the contact form's SMTP
// throttle, which has no non-IP backstop.
func TestRateLimiterKeyCapKeepsBlockedKeys(t *testing.T) {
	rl := newRateLimiter(2, time.Hour)

	const victim = "203.0.113.7"
	if !rl.allow(victim) || !rl.allow(victim) {
		t.Fatal("first two events should be allowed")
	}
	if rl.allow(victim) {
		t.Fatal("third event should be blocked")
	}

	// Flood past the cap with throwaway keys, as an address-rotating attacker does.
	for i := 0; i < maxLimiterKeys+pruneEvery+10; i++ {
		rl.allow(fmt.Sprintf("attacker-%d", i))
	}

	if rl.allow(victim) {
		t.Fatal("key-cap overflow reset a blocked key: flooding the limiter with " +
			"throwaway keys would clear everyone's counters")
	}
	if len(rl.hits) > maxLimiterKeys {
		t.Fatalf("tracked keys = %d, want <= %d: memory is unbounded", len(rl.hits), maxLimiterKeys)
	}
}

// TestClientIPTrustsProxyOnly: X-Forwarded-For may only be believed when the
// request actually came from a proxy. A client reaching the app directly controls
// its own headers, so trusting them would hand it a fresh limiter key per request
// and silently disable every per-IP throttle.
func TestClientIPTrustsProxyOnly(t *testing.T) {
	cases := []struct {
		name, remoteAddr, xff, want string
	}{
		{"behind caddy on a container network", "172.18.0.5:54321", "203.0.113.9, 172.18.0.1", "172.18.0.1"},
		{"loopback proxy", "127.0.0.1:8080", "198.51.100.4, 127.0.0.1", "127.0.0.1"},
		{"no forwarding header", "172.18.0.5:54321", "", "172.18.0.5"},
		// The dangerous one: a direct public client inventing a header.
		{"direct public client spoofing", "203.0.113.9:1234", "10.0.0.1", "203.0.113.9"},
		{"direct public client, no header", "203.0.113.9:1234", "", "203.0.113.9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.remoteAddr
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := clientIP(r); got != c.want {
				t.Errorf("clientIP = %q, want %q", got, c.want)
			}
		})
	}
}
