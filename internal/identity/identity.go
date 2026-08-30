// Package identity resolves the authenticated user from the trusted headers
// injected by the platform's Caddy forward_auth layer. This app implements no
// login of its own: Caddy authenticates the request against vps-scaffold-auth,
// strips any client-supplied identity headers, and re-injects the authoritative
// values Remote-User / Remote-Email / Remote-Groups before proxying to us.
//
// See vps-scaffold conventions: header names are Remote-* (not X-Auth-*), and
// Groups is a comma-separated list containing "admin" and/or "user".
package identity

import (
	"context"
	"crypto/subtle"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type ctxKey struct{}

// User is the resolved identity for a request.
type User struct {
	Email  string
	Name   string
	Groups []string
}

// IsAdmin reports whether the user is in the admin group.
func (u User) IsAdmin() bool {
	for _, g := range u.Groups {
		if g == "admin" {
			return true
		}
	}
	return false
}

// Decoder resolves a User from a request (e.g. from the app's signed session
// cookie). It reports ok=false when no valid identity is present.
//
// It receives the ResponseWriter so an implementation can renew the credential it
// just validated — a stateless signed cookie has no other moment at which to slide
// its expiry forward, and without renewal an active user is signed out abruptly
// when the fixed TTL elapses.
type Decoder func(http.ResponseWriter, *http.Request) (User, bool)

// fromTrustedProxy reports whether the identity headers on this request may be
// believed, judged by the peer being loopback or a private/link-local address —
// which is what the far end of a container network looks like.
//
// Without this check the headers are trusted from ANY peer, and the consequence
// is total: an operator who publishes the container port directly (a documented
// posture) while leaving APP_OIDC_ISSUER unset gets an app where any caller on
// the internet becomes any user, or an admin, by sending two headers. Caddy
// strips client-supplied copies, but that only helps while Caddy is the only way
// in. This is the same peer test clientIP already applies to X-Forwarded-For, and
// the more dangerous header deserves it at least as much.
//
// An unparseable peer is untrusted. Failing closed here costs a sign-in outage,
// which is loud; failing open costs the whole authorization model, silently.
func fromTrustedProxy(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// lastSpoofLog throttles the warning below. A rejected identity header is either
// a misconfigured deployment or someone probing for exactly this hole, and both
// are worth a log line — but neither is worth one per request under a flood.
var lastSpoofLog atomic.Int64

const spoofLogEvery = int64(time.Minute)

func warnUntrustedIdentity(remoteAddr string) {
	now := time.Now().UnixNano()
	prev := lastSpoofLog.Load()
	if now-prev < spoofLogEvery || !lastSpoofLog.CompareAndSwap(prev, now) {
		return
	}
	log.Printf("SECURITY: ignoring Remote-* identity headers from untrusted peer %s. "+
		"These are only believed from a loopback/private peer (the reverse proxy). If sign-in is "+
		"broken, the app is reachable other than through the proxy — do not expose its port directly.",
		remoteAddr)
}

// warnMissingProxySecret is the shared-secret sibling of warnUntrustedIdentity:
// a private peer sent identity headers without the configured X-Proxy-Secret.
// Either the proxy's env lost the secret (sign-in outage — loud and quick to
// spot) or something on a private network is impersonating the proxy.
func warnMissingProxySecret(remoteAddr string) {
	now := time.Now().UnixNano()
	prev := lastSpoofLog.Load()
	if now-prev < spoofLogEvery || !lastSpoofLog.CompareAndSwap(prev, now) {
		return
	}
	log.Printf("SECURITY: ignoring Remote-* identity headers from private peer %s: PROXY_SECRET is set but the request carries no matching X-Proxy-Secret. "+
		"If sign-in is broken, the reverse proxy's PSTONN_PROXY_SECRET env does not match the app's PROXY_SECRET.", remoteAddr)
}

// Middleware resolves the request identity.
//
// trustForwardAuth MUST be true only when the app runs behind the platform's
// forward_auth layer (its own OIDC login disabled). In that mode the Remote-*
// headers are authoritative (Caddy strips any client-supplied copies and
// re-injects the verified values) — but only when they actually arrive from the
// proxy, which fromTrustedProxy checks. When the app runs its OWN OIDC login
// instead, trustForwardAuth is false and Remote-* headers are ignored entirely,
// so an attacker cannot present a Remote-Email header to override the verified
// session cookie.
//
// Precedence: (1) Remote-* headers when trustForwardAuth AND the peer is the
// proxy; (2) the app's signed session cookie via decode (OIDC login); (3)
// devEmail, a local/standalone fallback that MUST be empty in production. decode
// may be nil.
// proxySecretHeader is presented by the reverse proxy alongside the Remote-*
// identity headers when a shared secret is configured (PROXY_SECRET). The
// private-peer test answers "did this arrive over a container network?"; the
// secret answers "did it come from OUR proxy?" — a compromised neighbour on a
// private network fails the second even where it could pass the first.
const proxySecretHeader = "X-Proxy-Secret"

// proxyPresentsSecret reports whether the request carries the configured shared
// secret. An empty configured secret means this deployment has not opted in and
// the peer test stands alone (self-host compatibility; the proxy-side header is
// then simply absent too).
func proxyPresentsSecret(r *http.Request, secret string) bool {
	if secret == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get(proxySecretHeader)), []byte(secret)) == 1
}

func Middleware(devEmail string, decode Decoder, trustForwardAuth bool, proxySecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var u User
			if trustForwardAuth {
				if email := strings.ToLower(strings.TrimSpace(r.Header.Get("Remote-Email"))); email != "" {
					if fromTrustedProxy(r.RemoteAddr) && proxyPresentsSecret(r, proxySecret) {
						u = User{
							Email:  email,
							Name:   strings.TrimSpace(r.Header.Get("Remote-User")),
							Groups: splitGroups(r.Header.Get("Remote-Groups")),
						}
					} else if !fromTrustedProxy(r.RemoteAddr) {
						warnUntrustedIdentity(r.RemoteAddr)
					} else {
						warnMissingProxySecret(r.RemoteAddr)
					}
				}
			}
			if u.Email == "" && decode != nil {
				if du, ok := decode(w, r); ok {
					u = du
				}
			}
			if u.Email == "" && devEmail != "" {
				u = User{Email: devEmail, Name: devEmail, Groups: []string{"user", "admin"}}
			}
			ctx := context.WithValue(r.Context(), ctxKey{}, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromContext returns the resolved user and whether one was present.
func FromContext(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(ctxKey{}).(User)
	return u, ok && u.Email != ""
}

func splitGroups(raw string) []string {
	var out []string
	for _, g := range strings.Split(raw, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}
