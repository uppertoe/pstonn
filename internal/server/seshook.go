package server

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/store"
)

// snsMessage is the envelope Amazon SNS POSTs to an HTTPS subscriber.
type snsMessage struct {
	Type             string `json:"Type"`
	MessageID        string `json:"MessageId"`
	Token            string `json:"Token"`
	TopicARN         string `json:"TopicArn"`
	Subject          string `json:"Subject"`
	Message          string `json:"Message"`
	SubscribeURL     string `json:"SubscribeURL"`
	Timestamp        string `json:"Timestamp"`
	SignatureVersion string `json:"SignatureVersion"`
	Signature        string `json:"Signature"`
	SigningCertURL   string `json:"SigningCertURL"`
}

// sesEvent is the subset of an SES event notification we act on. SES nests this
// as a JSON string inside the SNS envelope's Message field.
type sesEvent struct {
	NotificationType string `json:"notificationType"`
	EventType        string `json:"eventType"` // config-set events use this name instead
	Bounce           struct {
		BounceType        string `json:"bounceType"`    // Permanent | Transient | Undetermined
		BounceSubType     string `json:"bounceSubType"` // e.g. General, NoEmail, Suppressed
		BouncedRecipients []struct {
			EmailAddress   string `json:"emailAddress"`
			DiagnosticCode string `json:"diagnosticCode"`
			Status         string `json:"status"`
		} `json:"bouncedRecipients"`
	} `json:"bounce"`
	Complaint struct {
		ComplaintFeedbackType string `json:"complaintFeedbackType"`
		ComplainedRecipients  []struct {
			EmailAddress string `json:"emailAddress"`
		} `json:"complainedRecipients"`
	} `json:"complaint"`
}

// maxSNSBody bounds the POST body. SES notifications are a few KB; the endpoint
// is public, so it must not be a memory sink.
const maxSNSBody = 256 << 10

// sesHook consumes SES bounce and complaint notifications delivered via SNS, and
// records undeliverable addresses so the app stops mailing them. Without this the
// app keeps sending to a dead address forever — retrying a hard bounce is what
// gets a sending domain's reputation destroyed and, on SES, its sending paused.
//
// The endpoint is public (SNS cannot present a bearer token), so authenticity
// rests entirely on: the SNS cryptographic signature, the signing certificate
// coming from an AWS host, and the topic ARN matching the one we configured.
// Anything else is refused — a forged bounce would let anyone silence any user's
// notifications, which is a denial of service against a fine-avoidance tool.
func (s *Server) sesHook(w http.ResponseWriter, r *http.Request) {
	// Throttle before anything else. Verifying a message can cost an outbound TLS
	// fetch of a signing certificate, and the only identifier gating that work is a
	// topic ARN — an identifier, not a secret — so an unthrottled caller turns one
	// cheap POST into one of our requests to AWS, indefinitely. SES delivers each
	// event once and retries a handful of times, so a real topic is nowhere near
	// this ceiling.
	if !s.sesHookLimit.allow(rateLimitKey(r)) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSNSBody))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var m snsMessage
	if err := json.Unmarshal(body, &m); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Topic first: cheapest check, and it scopes everything that follows to the
	// one topic this deployment owns.
	if m.TopicARN != s.cfg.SESTopicARN {
		alog.Warnf("ses hook: refusing message for unexpected topic %q", m.TopicARN)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Freshness BEFORE the signature. A signature is valid forever, so without this
	// check any captured notification can be replayed indefinitely — replaying a
	// bounce is close to idempotent, but it still bumps the hit counter and refreshes
	// last_seen, which is enough to keep an address suppressed past the point it
	// would have aged out. It runs first because parsing a timestamp costs nothing
	// while verification may have to go and fetch a certificate: the order is what
	// stops a caller spending our outbound bandwidth on messages we were always
	// going to refuse.
	if !freshSNSTimestamp(m.Timestamp, time.Now()) {
		alog.Warnf("ses hook: refusing message with stale or unparseable timestamp %q", m.Timestamp)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := verifySNSSignature(r.Context(), s.snsCert, &m); err != nil {
		alog.Errorf("ses hook: signature verification failed: %v", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	switch m.Type {
	case "SubscriptionConfirmation":
		// Confirm by fetching the URL SNS supplied. It is signature-verified above
		// and host-checked here, so this cannot be pointed at an arbitrary target.
		if err := confirmSNSSubscription(r.Context(), m.SubscribeURL); err != nil {
			alog.Errorf("ses hook: subscription confirmation failed: %v", err)
			http.Error(w, "confirmation failed", http.StatusBadGateway)
			return
		}
		alog.Infof("ses hook: confirmed SNS subscription for topic %s", m.TopicARN)
	case "Notification":
		if err := s.handleSESEvent(r, m.Message); err != nil {
			// A suppression write failed (a full data volume, a read-only remount). Ack
			// it with 200 and SNS deletes the message — a bounce mostly self-heals on the
			// next send, but a spam complaint is ONE-SHOT and the row it would create is
			// never pruned, so a lost complaint is a reputation event we can never recover.
			// Return 500 instead: SNS redelivers, and SuppressAddress is an idempotent
			// upsert so the retry is safe. (Bounded by snsMaxSkew — SNS stops retrying
			// past the freshness window — but that beats dropping it on the first failure.)
			alog.Errorf("ses hook: suppression write failed, asking SNS to retry: %v", err)
			http.Error(w, "temporary storage error", http.StatusInternalServerError)
			return
		}
	case "UnsubscribeConfirmation":
		// Someone unsubscribed our endpoint. That silently disables bounce handling,
		// so make it loud rather than letting the app drift back to no feedback.
		alog.Warnf("ses hook: our SNS subscription was cancelled for %s", m.TopicARN)
	default:
		alog.Infof("ses hook: ignoring message type %q", m.Type)
	}
	w.WriteHeader(http.StatusOK)
}

// handleSESEvent records suppressions from one SES notification. Only PERMANENT
// bounces and complaints suppress: a transient bounce (full mailbox, greylisting)
// is exactly what the outbox's retry is for, and suppressing on it would mute a
// user over a temporary condition.
// handleSESEvent records suppressions from one SES notification. It returns a
// non-nil error ONLY when a suppression write failed and the event is worth
// redelivering — the caller turns that into a 500 so SNS retries. An unparseable or
// irrelevant payload returns nil (acked): it will never parse or suppress, so retries
// would only have SNS hammer a body it can never accept for the whole retry window.
func (s *Server) handleSESEvent(r *http.Request, raw string) error {
	var ev sesEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		alog.Warnf("ses hook: unparseable SES event: %v", err)
		return nil
	}
	kind := ev.NotificationType
	if kind == "" {
		kind = ev.EventType
	}
	ctx := r.Context()
	// Remember the last write failure but keep processing the other recipients, so a
	// single bad row does not drop the suppressions that CAN be recorded. Any failure
	// still makes the whole event retry (the upsert is idempotent, so re-recording the
	// ones that already landed is harmless).
	var writeErr error
	switch strings.ToLower(kind) {
	case "bounce":
		if !strings.EqualFold(ev.Bounce.BounceType, "Permanent") {
			alog.Infof("ses hook: %s/%s bounce — not suppressing (retryable)", ev.Bounce.BounceType, ev.Bounce.BounceSubType)
			return nil
		}
		for _, rcpt := range ev.Bounce.BouncedRecipients {
			detail := strings.TrimSpace(rcpt.Status + " " + rcpt.DiagnosticCode)
			if detail == "" {
				detail = ev.Bounce.BounceSubType
			}
			if err := s.store.SuppressAddress(ctx, rcpt.EmailAddress, store.SuppressBounce, detail); err != nil {
				alog.Infof("ses hook: suppress %s: %v", notify.RedactEmail(rcpt.EmailAddress), err)
				writeErr = err
				continue
			}
			// The address and the receiving server's diagnostic (which is free text
			// from a third party, and often quotes the address back) go in the
			// suppression row, which the admin page shows and PruneSuppressions
			// clears. The log needs only the fixed-vocabulary subtype.
			alog.Infof("ses hook: suppressed %s (permanent bounce: %s)", notify.RedactEmail(rcpt.EmailAddress), ev.Bounce.BounceSubType)
		}
	case "complaint":
		// RFC 5965 defines "not-spam" as the recipient moving our mail OUT of their
		// spam folder — the opposite of a complaint, and SES forwards it as one.
		// Acting on it would suppress someone for rescuing us, and a complaint row is
		// the one kind that is never pruned and never user-clearable.
		if strings.EqualFold(ev.Complaint.ComplaintFeedbackType, "not-spam") {
			alog.Infof("ses hook: ignoring a not-spam feedback report (the recipient un-junked our mail)")
			return nil
		}
		for _, rcpt := range ev.Complaint.ComplainedRecipients {
			if err := s.store.SuppressAddress(ctx, rcpt.EmailAddress, store.SuppressComplaint, ev.Complaint.ComplaintFeedbackType); err != nil {
				alog.Infof("ses hook: suppress %s: %v", notify.RedactEmail(rcpt.EmailAddress), err)
				writeErr = err
				continue
			}
			alog.Infof("ses hook: suppressed %s (spam complaint)", notify.RedactEmail(rcpt.EmailAddress))
		}
	case "delivery":
		// Nothing to do; subscribing to deliveries is optional and harmless.
	default:
		alog.Infof("ses hook: ignoring SES event %q", kind)
	}
	return writeErr
}

// snsMaxSkew bounds how far an SNS message's own timestamp may be from now.
// Generous in both directions: SNS retries a failing endpoint for a while, and
// neither clock is guaranteed exact. Small enough that a captured message stops
// being replayable the same day.
const snsMaxSkew = 2 * time.Hour

// freshSNSTimestamp reports whether an SNS Timestamp is close enough to now. An
// absent or unparseable timestamp is refused rather than trusted: every genuine
// message has one.
func freshSNSTimestamp(ts string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return false
	}
	d := now.Sub(t)
	if d < 0 {
		d = -d
	}
	return d <= snsMaxSkew
}

// certCache memoises SNS signing-certificate lookups. AWS rotates them rarely,
// and re-fetching per notification would make a bounce storm into an outbound
// request storm.
//
// Both outcomes are cached. Caching only successes made every REFUSED URL a free
// outbound fetch, so a caller who varied the certificate filename spent our
// bandwidth once per request; a negative entry makes the second attempt at a bad
// URL cost nothing.
type certCache struct {
	mu    sync.Mutex
	certs map[string]cachedCert
	http  *http.Client
}

// cachedCert is one lookup outcome: a usable certificate, or the error that
// lookup produced. err != nil marks a negative entry.
type cachedCert struct {
	cert    *x509.Certificate
	err     error
	expires time.Time
}

const (
	// maxCachedCerts is far above the handful of regional SNS signing endpoints any
	// real deployment sees, so reaching it means someone is feeding us URLs.
	maxCachedCerts = 64
	// certTTL bounds how long a good certificate is reused. AWS rotates its signing
	// certificate, and an entry that never expires pins us to the old key until the
	// process restarts.
	certTTL = 6 * time.Hour
	// certNegTTL is short on purpose: a negative entry must absorb a flood without
	// making a genuine, transient fetch failure (a blip reaching AWS) stick long
	// enough to drop real bounce notifications.
	certNegTTL = 5 * time.Minute
)

func newCertCache() *certCache {
	return &certCache{
		certs: map[string]cachedCert{},
		http:  &http.Client{Timeout: 10 * time.Second},
	}
}

// errUntrustedCertHost rejects a signing certificate URL that is not an SNS
// host. Without this check the signature proves nothing: an attacker would sign
// a forged notification with their own key and point us at their own cert.
var errUntrustedCertHost = errors.New("signing certificate URL is not an SNS host")

// snsCertFile is the filename shape AWS publishes signing certificates under.
// The host check alone left the path free, which means ANY bytes served from an
// SNS endpoint that happen to contain a PEM block would have been accepted as a
// trust anchor — AWS's own verifier libraries constrain the path for exactly this
// reason. Pinning the shape also makes the cache key canonical, so a caller
// cannot mint unlimited distinct keys (and unlimited fetches) out of one real URL.
var snsCertFile = regexp.MustCompile(`^SimpleNotificationService-[A-Za-z0-9._-]{1,80}\.pem$`)

// certKey validates a signing-certificate URL and returns the cache key for it.
// Any query or fragment is refused outright rather than normalised away: genuine
// SNS certificate URLs have neither, and tolerating them was what let `?n=1`,
// `?n=2`, ... each be a separate cache miss.
func certKey(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || !isSNSHost(u.Host) {
		return "", fmt.Errorf("%w: %q", errUntrustedCertHost, rawURL)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("signing certificate URL carries a query, fragment or userinfo: %q", rawURL)
	}
	dir, file := path.Split(u.Path)
	if dir != "/" || !snsCertFile.MatchString(file) {
		return "", fmt.Errorf("signing certificate URL path is not a SimpleNotificationService-*.pem file: %q", rawURL)
	}
	return "https://" + strings.ToLower(u.Host) + u.Path, nil
}

func (c *certCache) get(ctx context.Context, rawURL string) (*x509.Certificate, error) {
	key, err := certKey(rawURL)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	c.mu.Lock()
	e, ok := c.certs[key]
	c.mu.Unlock()
	if ok && now.Before(e.expires) {
		if e.err != nil {
			return nil, e.err
		}
		// Re-check the dates on EVERY use, not just at fetch: a cached certificate
		// outlives its own validity window otherwise, and "we trusted it an hour ago"
		// is not a reason to keep trusting a signing key that has expired.
		if err := checkCertWindow(e.cert, now); err != nil {
			return nil, err
		}
		return e.cert, nil
	}

	// The fetch happens with the lock RELEASED: it is a network call, and holding
	// the cache mutex across it would stall every other in-flight notification
	// behind one slow AWS response. Concurrent misses for the same URL can each
	// fetch; that is bounded by this route's per-IP throttle and by the negative
	// entry below, and duplicating a rare fetch is much cheaper than serialising
	// the handler on a remote host.
	cert, ferr := fetchSNSCert(ctx, c.http, key)
	if ferr != nil && (ctx.Err() != nil || errors.Is(ferr, context.Canceled) || errors.Is(ferr, context.DeadlineExceeded)) {
		// A cancelled or timed-out REQUEST says nothing about the URL — SNS hanging up
		// mid-fetch is routine — so it must not be remembered as a refusal and shut
		// the next few minutes of genuine notifications out.
		return nil, ferr
	}
	entry := cachedCert{cert: cert, err: ferr, expires: now.Add(certTTL)}
	if ferr != nil {
		entry.expires = now.Add(certNegTTL)
	}
	c.mu.Lock()
	c.evictLocked(now)
	c.certs[key] = entry
	c.mu.Unlock()
	if ferr != nil {
		return nil, ferr
	}
	return cert, nil
}

// evictLocked keeps the map under maxCachedCerts. Expired entries go first, and
// only if that is not enough does the entry closest to expiry go — dropping one
// entry rather than clearing the map, so a flood of junk URLs cannot evict the one
// certificate every real notification needs and turn each genuine event into a
// fresh fetch.
func (c *certCache) evictLocked(now time.Time) {
	if len(c.certs) < maxCachedCerts {
		return
	}
	for k, e := range c.certs {
		if !now.Before(e.expires) {
			delete(c.certs, k)
		}
	}
	for len(c.certs) >= maxCachedCerts {
		var oldestKey string
		var oldest time.Time
		for k, e := range c.certs {
			if oldestKey == "" || e.expires.Before(oldest) {
				oldestKey, oldest = k, e.expires
			}
		}
		delete(c.certs, oldestKey)
	}
}

// fetchSNSCert retrieves and parses one signing certificate. url has already been
// validated by certKey.
func fetchSNSCert(ctx context.Context, client *http.Client, url string) (*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch signing cert: %s", resp.Status)
	}
	pemBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("signing cert is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := checkCertWindow(cert, time.Now()); err != nil {
		return nil, err
	}
	return cert, nil
}

// checkCertWindow rejects an expired or not-yet-valid certificate. Parsing alone
// never checks this. The chain itself is covered by the TLS handshake against the
// SNS host (a public CA vouches for it), so the dates are what is left to verify.
func checkCertWindow(cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return errors.New("no signing certificate")
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("signing cert is outside its validity window (%s to %s)",
			cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// isSNSHost reports whether a host is an Amazon SNS endpoint, which is the only
// place a genuine signing certificate is published.
//
// "ends with .amazonaws.com" is NOT good enough, and the difference is the whole
// security of this endpoint. Anyone with an AWS account can serve arbitrary files
// from *.s3.amazonaws.com, so a suffix check lets an attacker publish their OWN
// certificate on an "AWS host", sign a forged bounce with the matching key, and
// pass every check here. They could then permanently suppress any address they
// named — and a complaint row is never pruned, never user-clearable and invisible
// to the household, so it silently kills the notifications this app exists to
// send. Only sns.<region>.amazonaws.com (and the China partition equivalent) may
// serve a signing cert; those hosts serve SNS's API, not attacker-supplied files.
func isSNSHost(host string) bool {
	h := strings.ToLower(host)
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i] // strip any port
	}
	rest, ok := strings.CutPrefix(h, "sns.")
	if !ok {
		return false
	}
	region, ok := strings.CutSuffix(rest, ".amazonaws.com.cn")
	if !ok {
		if region, ok = strings.CutSuffix(rest, ".amazonaws.com"); !ok {
			return false
		}
	}
	return isAWSRegion(region)
}

// isAWSRegion reports whether s looks like a single region label ("ap-southeast-2").
// Rejecting dots is what stops "sns.evil.com.amazonaws.com" and any other attempt
// to smuggle extra labels into the region position.
func isAWSRegion(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// snsSigningFields is the exact set and order of fields AWS signs, per message
// type. Order matters: the string to sign is these key/value pairs concatenated
// in this sequence, each followed by a newline.
func snsSigningFields(m *snsMessage) []struct{ key, val string } {
	if m.Type == "SubscriptionConfirmation" || m.Type == "UnsubscribeConfirmation" {
		return []struct{ key, val string }{
			{"Message", m.Message},
			{"MessageId", m.MessageID},
			{"SubscribeURL", m.SubscribeURL},
			{"Timestamp", m.Timestamp},
			{"Token", m.Token},
			{"TopicArn", m.TopicARN},
			{"Type", m.Type},
		}
	}
	f := []struct{ key, val string }{
		{"Message", m.Message},
		{"MessageId", m.MessageID},
	}
	if m.Subject != "" { // Subject is signed only when present
		f = append(f, struct{ key, val string }{"Subject", m.Subject})
	}
	return append(f,
		struct{ key, val string }{"Timestamp", m.Timestamp},
		struct{ key, val string }{"TopicArn", m.TopicARN},
		struct{ key, val string }{"Type", m.Type},
	)
}

// Only SignatureVersion 2 (RSA-SHA256) is accepted.
//
// SignatureVersion is NOT itself covered by the signature, so accepting more than
// one version lets the caller choose the digest. Version 1 is RSA-SHA1 over a
// string that includes remote-influenced text (an SMTP diagnosticCode echoed back
// by whatever server rejected our mail), and the regional signing key is shared by
// every SNS topic in the region — an attacker can therefore have AWS sign material
// of their own choosing and needs only a SHA-1 collision with a message naming our
// topic. Chosen-prefix SHA-1 collisions are affordable.
//
// This was previously pinned by observation rather than refused outright, because
// SNS emits version 1 until the topic's SignatureVersion attribute is set, and
// refusing it on a topic that still spoke it would have silently stopped ALL
// bounce and complaint processing — after which the app keeps mailing addresses
// the provider has told us are dead, which is how a sending domain gets blocked.
// The attribute is now set on the live topic (and by
// deploy/aws-ses-hook-setup.py), verified end to end with a real bounce, so the
// weak version is gone rather than merely unreachable.

// verifySNSSignature checks the message really came from the SNS topic it claims.
//
// Every cheap check runs before the certificate lookup, which may go to the
// network: an attacker must not be able to make us fetch anything by sending a
// message that was never going to verify.
func verifySNSSignature(ctx context.Context, cache *certCache, m *snsMessage) error {
	if m.Signature == "" || m.SigningCertURL == "" {
		return errors.New("message is unsigned")
	}
	if m.SignatureVersion != "2" {
		return fmt.Errorf("refusing SignatureVersion %q: only 2 (RSA-SHA256) is accepted; "+
			"set the topic's SignatureVersion attribute to 2", m.SignatureVersion)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("signature is not base64: %w", err)
	}
	var sb strings.Builder
	for _, f := range snsSigningFields(m) {
		sb.WriteString(f.key)
		sb.WriteString("\n")
		sb.WriteString(f.val)
		sb.WriteString("\n")
	}
	digest := sha256.Sum256([]byte(sb.String()))
	cert, err := cache.get(ctx, m.SigningCertURL)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("signing certificate is not RSA")
	}
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
}

// confirmSNSSubscription completes the SNS handshake by fetching SubscribeURL.
// The URL is host-checked again here (defence in depth: the signature check
// already covers it, but this function is what actually makes the request).
func confirmSNSSubscription(ctx context.Context, subscribeURL string) error {
	u, err := url.Parse(subscribeURL)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || !isSNSHost(u.Host) {
		return fmt.Errorf("%w: %q", errUntrustedCertHost, subscribeURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subscribeURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("confirm returned %s", resp.Status)
	}
	return nil
}
