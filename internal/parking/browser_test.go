package parking

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestBrowserTransportSetsUA confirms every outbound request carries a browser
// User-Agent (never Go's default) and the client-hint headers, and that an
// explicitly-set header is not overwritten.
func TestBrowserTransportSetsUA(t *testing.T) {
	var gotUA, gotChUA, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotChUA = r.Header.Get("sec-ch-ua")
		gotAccept = r.Header.Get("Accept")
	}))
	defer srv.Close()

	client := &http.Client{Transport: browserTransport{base: http.DefaultTransport}}

	// No headers set: transport must supply them.
	if _, err := client.Get(srv.URL); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotUA, "Go-http-client") || !strings.Contains(gotUA, "Chrome/") {
		t.Fatalf("User-Agent = %q, want a Chrome UA and never the Go default", gotUA)
	}
	if gotChUA == "" {
		t.Fatal("sec-ch-ua header was not set")
	}

	// Caller-set header must survive.
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept", "application/json")
	if _, err := client.Do(req); err != nil {
		t.Fatal(err)
	}
	if gotAccept != "application/json" {
		t.Fatalf("caller Accept overwritten: got %q", gotAccept)
	}
}

func TestParseRetryAfter(t *testing.T) {
	mk := func(v string) *http.Response {
		h := http.Header{}
		if v != "" {
			h.Set("Retry-After", v)
		}
		return &http.Response{Header: h}
	}
	if d := parseRetryAfter(mk("120")); d != 120*time.Second {
		t.Fatalf("delta-seconds: got %v, want 120s", d)
	}
	if d := parseRetryAfter(mk("")); d != 0 {
		t.Fatalf("absent header: got %v, want 0", d)
	}
	if d := parseRetryAfter(mk("garbage")); d != 0 {
		t.Fatalf("garbage: got %v, want 0", d)
	}
}

// TestCooldownBackoff confirms a penalised owner enters cooldown and that a
// success clears it.
func TestCooldownBackoff(t *testing.T) {
	c := &Client{}
	const owner = "a@b.com"
	if _, blocked := c.cooldownFor(owner); blocked {
		t.Fatal("owner should start un-penalised")
	}
	c.penalize(owner, 0)
	if _, blocked := c.cooldownFor(owner); !blocked {
		t.Fatal("owner should be in cooldown after a penalty")
	}
	c.clearPenalty(owner)
	if _, blocked := c.cooldownFor(owner); blocked {
		t.Fatal("cooldown should clear after success")
	}
}
