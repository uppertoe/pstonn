package server

import (
	"fmt"
	"net/http"
	"strings"
)

// The saved pages: a guest link or the quick picker installed on a phone's
// home screen, and the app itself. With no connection an installed page showed
// the browser's own "no internet" screen. A small service worker now stands in
// front of every navigation: it tries the network and, only when that fails
// outright, serves the branded /offline page it cached at install. It caches
// nothing else — never a guest page, never a signed-in page — and it never
// answers a fragment or poll request (those fail as before, and the page's own
// sendError handler says the phone is offline), so a swapped fragment can
// never be the offline page's markup.
//
// Both paths must be public at the proxy (the @public matcher in
// deploy/pstonn.caddy and its live copy): a worker script behind forward-auth
// registers nothing, silently.

// offlineAssets is what the worker caches at install: the page and the static
// files its layout pulls (the stylesheet, the wordmark font, the icons). All
// carry the content hash, so a deploy installs a fresh set under a new cache
// name and the activate step drops the old one.
func offlineAssets() []string {
	return []string{
		"/offline",
		asset("app.css"),
		asset("spacegrotesk-wordmark.woff2"),
		asset("icon-192.png"),
		asset("icon-180.png"),
	}
}

// offline renders the page the worker serves in place of a navigation that
// could not reach the server: plain, branded, and honest that nothing changed.
func (s *Server) offline(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	s.render(w, s.publicPage(r, "offline"))
}

// serviceWorker serves the worker script with this build's asset URLs baked
// in. no-cache so a browser re-checks it on each navigation (they cap a
// worker script's freshness at a day regardless); the cache name carries the
// static version, so the byte-for-byte comparison browsers make finds a change
// exactly when a deploy changed what the offline page needs.
func (s *Server) serviceWorker(w http.ResponseWriter, r *http.Request) {
	quoted := make([]string, 0, len(offlineAssets()))
	for _, a := range offlineAssets() {
		quoted = append(quoted, fmt.Sprintf("%q", a))
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprintf(w, serviceWorkerJS, staticVersion, strings.Join(quoted, ", "))
}

// serviceWorkerJS is the worker. Deliberately minimal: a worker sits in front
// of the whole app for every visitor until the next one replaces it, so it
// does one thing. %s are the static version and the asset list.
const serviceWorkerJS = `// p.stonn offline page. Serves /offline when a navigation cannot reach the
// server; caches nothing else and answers nothing else.
var CACHE = 'pstonn-offline-%s';
var ASSETS = [%s];
var OFFLINE = ASSETS[0];

self.addEventListener('install', function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(ASSETS); }).then(function () { return self.skipWaiting(); }));
});

self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); }));
  }).then(function () { return self.clients.claim(); }));
});

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;
  if (req.mode === 'navigate') {
    // The network first, always; the cached page only when the request itself
    // fails (no connection), never for a server's own answer.
    e.respondWith(fetch(req).catch(function () { return caches.match(OFFLINE); }));
    return;
  }
  var url = new URL(req.url);
  if (url.origin === self.location.origin && ASSETS.indexOf(url.pathname + url.search) !== -1) {
    // The offline page's own assets: cached copy first, so the page draws with
    // no connection; otherwise the network as normal.
    e.respondWith(caches.match(req).then(function (hit) { return hit || fetch(req); }));
  }
});
`
