package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/config"
)

// The offline page and its worker are public, the worker names this build's
// asset URLs (so a deploy is a new worker and a new cache), and both paths are
// in the proxy's public matcher, where a worker behind forward-auth would
// register nothing.
func TestOfflinePageAndWorker(t *testing.T) {
	s := &Server{cfg: &config.Config{PublicBaseURL: "https://p.stonn.org", Domain: "stonn.org"}, terms: loadTerms("")}
	h := s.Handler()
	get := func(path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		return rr
	}
	page := get("/offline")
	if page.Code != 200 || !strings.Contains(page.Body.String(), "You&rsquo;re offline") || !strings.Contains(page.Body.String(), `<a class="btnlike" href="" hx-boost="false">Try again</a>`) {
		t.Fatalf("offline page = %d:\n%s", page.Code, excerpt(page.Body.String()))
	}
	if strings.Contains(page.Body.String(), "hx-get") || strings.Contains(page.Body.String(), "hx-post") {
		t.Fatal("the offline page carries a request it cannot make")
	}
	sw := get("/sw.js")
	if sw.Code != 200 || sw.Header().Get("Content-Type") != "text/javascript; charset=utf-8" || sw.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("worker = %d %v", sw.Code, sw.Header())
	}
	for _, want := range []string{"pstonn-offline-" + staticVersion, `"/offline"`, `"` + asset("app.css") + `"`, "req.mode === 'navigate'"} {
		if !strings.Contains(sw.Body.String(), want) {
			t.Fatalf("worker lacks %q:\n%s", want, sw.Body.String())
		}
	}
	for _, path := range []string{"GET /offline", "GET /sw.js"} {
		found := false
		for _, rt := range s.routes {
			if rt.methodPattern == path {
				found = true
				if rt.guard != guardPublic {
					t.Fatalf("%s is guarded %v, want public", path, rt.guard)
				}
			}
		}
		if !found {
			t.Fatalf("%s is not registered", path)
		}
	}
	caddy, err := os.ReadFile("../../deploy/pstonn.caddy")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(caddy), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "@public path ") {
			if !strings.Contains(line, " /offline") || !strings.Contains(line, " /sw.js") {
				t.Fatalf("the proxy's public matcher lacks the offline paths: %s", line)
			}
			return
		}
	}
	t.Fatal("no @public matcher in deploy/pstonn.caddy")
}
