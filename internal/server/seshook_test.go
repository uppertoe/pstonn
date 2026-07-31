package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // matching AWS SignatureVersion 1
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/store"
)

const testTopic = "arn:aws:sns:ap-southeast-2:123456789012:pstonn-ses-events"

// testCertURL has the shape AWS actually publishes signing certificates under
// (see snsCertFile); anything else is refused before a fetch is considered.
const testCertURL = "https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-test.pem"

// signSNS builds a signed SNS envelope the way AWS would, so the handler's
// verification path is exercised for real rather than stubbed out. Version 2
// (RSA-SHA256) is what the live topic emits and the only version accepted.
func signSNS(t *testing.T, key *rsa.PrivateKey, m *snsMessage) []byte {
	t.Helper()
	return signSNSVersion(t, key, m, "2")
}

// signSNSVersion can still produce a version-1 envelope, so the tests can prove the
// weak digest is refused rather than merely unused.
func signSNSVersion(t *testing.T, key *rsa.PrivateKey, m *snsMessage, version string) []byte {
	t.Helper()
	m.SignatureVersion = version
	m.SigningCertURL = testCertURL
	var sb strings.Builder
	for _, f := range snsSigningFields(m) {
		sb.WriteString(f.key)
		sb.WriteString("\n")
		sb.WriteString(f.val)
		sb.WriteString("\n")
	}
	var (
		hash   crypto.Hash
		digest []byte
	)
	if version == "2" {
		hash = crypto.SHA256
		sum := sha256.Sum256([]byte(sb.String()))
		digest = sum[:]
	} else {
		hash = crypto.SHA1
		sum := sha1.Sum([]byte(sb.String())) //nolint:gosec // AWS SignatureVersion 1
		digest = sum[:]
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newSESTestServer wires a Server with the SES hook enabled and a pre-seeded
// certificate cache, so no network fetch is attempted.
func newSESTestServer(t *testing.T) (*Server, *rsa.PrivateKey) {
	t.Helper()
	st, err := store.OpenSQLite(t.TempDir() + "/ses.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sns.amazonaws.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cache := newCertCache()
	cache.certs[testCertURL] = cachedCert{cert: cert, expires: time.Now().Add(time.Hour)}

	s := &Server{
		cfg:     &config.Config{DisplayLocation: time.UTC, SESTopicARN: testTopic},
		store:   st,
		terms:   loadTerms(""),
		snsCert: cache,
	}
	return s, key
}

func postSNS(s *Server, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/hooks/ses", strings.NewReader(string(body)))
	r.Host = "app.example.com"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// TestSESHookSuppresses covers the whole point of the endpoint: a permanent
// bounce and a complaint stop the app mailing that address, while a transient
// bounce does not (that is what retry is for).
func TestSESHookSuppresses(t *testing.T) {
	s, key := newSESTestServer(t)
	ctx := context.Background()

	permanent := `{"notificationType":"Bounce","bounce":{"bounceType":"Permanent","bounceSubType":"General",
	  "bouncedRecipients":[{"emailAddress":"dead@example.com","status":"5.1.1","diagnosticCode":"smtp; 550 user unknown"}]}}`
	body := signSNS(t, key, &snsMessage{
		Type: "Notification", MessageID: "m1", TopicARN: testTopic,
		Message: permanent, Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if w := postSNS(s, body); w.Code != http.StatusOK {
		t.Fatalf("permanent bounce = %d, want 200", w.Code)
	}
	bad, reason, err := s.store.IsSuppressed(ctx, "dead@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !bad || reason != store.SuppressBounce {
		t.Fatalf("dead@example.com suppressed=%v reason=%q, want true/bounce", bad, reason)
	}

	transient := `{"notificationType":"Bounce","bounce":{"bounceType":"Transient","bounceSubType":"MailboxFull",
	  "bouncedRecipients":[{"emailAddress":"full@example.com"}]}}`
	body = signSNS(t, key, &snsMessage{
		Type: "Notification", MessageID: "m2", TopicARN: testTopic,
		Message: transient, Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if w := postSNS(s, body); w.Code != http.StatusOK {
		t.Fatalf("transient bounce = %d, want 200", w.Code)
	}
	if bad, _, _ := s.store.IsSuppressed(ctx, "full@example.com"); bad {
		t.Fatal("a transient bounce must not suppress — retry is the correct response")
	}

	complaint := `{"notificationType":"Complaint","complaint":{"complaintFeedbackType":"abuse",
	  "complainedRecipients":[{"emailAddress":"Annoyed@Example.com"}]}}`
	body = signSNS(t, key, &snsMessage{
		Type: "Notification", MessageID: "m3", TopicARN: testTopic,
		Message: complaint, Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if w := postSNS(s, body); w.Code != http.StatusOK {
		t.Fatalf("complaint = %d, want 200", w.Code)
	}
	// Case-insensitive: the address is normalised on the way in and on lookup.
	bad, reason, _ = s.store.IsSuppressed(ctx, "annoyed@example.com")
	if !bad || reason != store.SuppressComplaint {
		t.Fatalf("complaint suppressed=%v reason=%q, want true/complaint", bad, reason)
	}
}

// TestSESHookRejectsForgery is the security boundary: a forged bounce would let
// anyone mute any user's notifications, so every unauthenticated shape must be
// refused and must not write anything.
func TestSESHookRejectsForgery(t *testing.T) {
	s, key := newSESTestServer(t)
	ctx := context.Background()
	msg := `{"notificationType":"Complaint","complaint":{"complainedRecipients":[{"emailAddress":"victim@example.com"}]}}`

	t.Run("unsigned is refused", func(t *testing.T) {
		body, _ := json.Marshal(snsMessage{
			Type: "Notification", MessageID: "x", TopicARN: testTopic, Message: msg,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		if w := postSNS(s, body); w.Code != http.StatusForbidden {
			t.Fatalf("unsigned = %d, want 403", w.Code)
		}
	})

	t.Run("wrong topic is refused", func(t *testing.T) {
		body := signSNS(t, key, &snsMessage{
			Type: "Notification", MessageID: "x", TopicARN: "arn:aws:sns:us-east-1:999:someone-else",
			Message: msg, Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		if w := postSNS(s, body); w.Code != http.StatusForbidden {
			t.Fatalf("wrong topic = %d, want 403", w.Code)
		}
	})

	t.Run("tampered message is refused", func(t *testing.T) {
		m := &snsMessage{
			Type: "Notification", MessageID: "x", TopicARN: testTopic, Message: msg,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
		body := signSNS(t, key, m)
		// Swap the victim after signing: the signature no longer covers the payload.
		tampered := strings.Replace(string(body), "victim@example.com", "other@example.com", 1)
		if w := postSNS(s, []byte(tampered)); w.Code != http.StatusForbidden {
			t.Fatalf("tampered = %d, want 403", w.Code)
		}
	})

	t.Run("signed by a foreign key is refused", func(t *testing.T) {
		attacker, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		body := signSNS(t, attacker, &snsMessage{
			Type: "Notification", MessageID: "x", TopicARN: testTopic, Message: msg,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		if w := postSNS(s, body); w.Code != http.StatusForbidden {
			t.Fatalf("foreign key = %d, want 403", w.Code)
		}
	})

	// Nothing above may have written a suppression.
	if bad, _, _ := s.store.IsSuppressed(ctx, "victim@example.com"); bad {
		t.Fatal("a forged notification suppressed an address")
	}
	if bad, _, _ := s.store.IsSuppressed(ctx, "other@example.com"); bad {
		t.Fatal("a tampered notification suppressed an address")
	}
}

// TestSESHookCertHostCheck locks the check that makes the signature meaningful:
// a certificate URL that is not an AWS host must be refused outright, because
// otherwise an attacker signs with their own key and supplies their own cert.
func TestSESHookCertHostCheck(t *testing.T) {
	for _, host := range []string{
		"https://evil.example.com/SimpleNotificationService-a.pem",
		"https://sns.amazonaws.com.evil.tld/SimpleNotificationService-a.pem",
		"https://evil-amazonaws.com/SimpleNotificationService-a.pem",
		"http://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-a.pem", // not https
		// The dangerous near-miss: anyone with an AWS account can serve arbitrary
		// files from these hosts, so accepting them means accepting an
		// attacker-supplied signing key. "Ends with .amazonaws.com" is NOT the
		// property we need — only SNS's own regional endpoints are.
		"https://my-bucket.s3.amazonaws.com/SimpleNotificationService-a.pem",
		"https://s3.ap-southeast-2.amazonaws.com/SimpleNotificationService-a.pem",
		"https://sns.evil.com.amazonaws.com/SimpleNotificationService-a.pem", // extra label in the region slot
		"https://notsns.ap-southeast-2.amazonaws.com/SimpleNotificationService-a.pem",
	} {
		if _, err := newCertCache().get(context.Background(), host); err == nil {
			t.Fatalf("cert URL %q was accepted, want rejection", host)
		}
	}
	// Genuine SNS endpoints must still pass the host check. They fail later (no
	// server is listening), so assert on WHICH error came back.
	for _, host := range []string{
		"https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-1234.pem",
		"https://sns.us-east-1.amazonaws.com/SimpleNotificationService-1234.pem",
		"https://sns.cn-north-1.amazonaws.com.cn/SimpleNotificationService-1234.pem",
	} {
		if _, err := certKey(host); err != nil {
			t.Fatalf("cert URL %q was rejected (%v), want it allowed", host, err)
		}
	}
}

// TestSNSCertURLPathConstrained: the host check alone leaves the PATH free, and
// an SNS endpoint serves plenty of bytes that are not a signing certificate. AWS's
// own verifiers pin the filename shape; so do we, and the constraint doubles as a
// canonical cache key so `?n=1`, `?n=2`, ... cannot mint unlimited cache misses.
func TestSNSCertURLPathConstrained(t *testing.T) {
	for _, raw := range []string{
		"https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-x.pem?n=1", // query
		"https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-x.pem#f",   // fragment
		"https://sns.ap-southeast-2.amazonaws.com/cert.pem",                            // wrong name
		"https://sns.ap-southeast-2.amazonaws.com/",                                    // no file
		"https://sns.ap-southeast-2.amazonaws.com/sub/SimpleNotificationService-x.pem", // not at the root
		"https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-x.pem.txt", // not a .pem
		"https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-.pem/../x", // traversal
		"https://user:pw@sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-x.pem",
	} {
		if _, err := certKey(raw); err == nil {
			t.Fatalf("cert URL %q was accepted, want rejection", raw)
		}
	}
	// Two spellings of the same URL must be ONE cache key, or the cache is a
	// fetch amplifier rather than a fetch preventer.
	a, err := certKey("https://SNS.ap-southeast-2.amazonaws.com/SimpleNotificationService-x.pem")
	if err != nil {
		t.Fatal(err)
	}
	b, err := certKey(testCertURL)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("different certificates share a cache key: %q", a)
	}
	c, _ := certKey("https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-x.pem")
	if a != c {
		t.Fatalf("host case changed the cache key: %q vs %q", a, c)
	}
}

// countingTransport serves one certificate and counts how many times it was
// actually fetched, which is the quantity G4 is about: a caller must not be able
// to turn each POST into an outbound request.
type countingTransport struct {
	pem  []byte
	code int
	n    int
}

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.n++
	code := c.code
	if code == 0 {
		code = http.StatusOK
	}
	return &http.Response{
		StatusCode: code,
		Status:     http.StatusText(code),
		Body:       io.NopCloser(bytes.NewReader(c.pem)),
		Header:     http.Header{},
	}, nil
}

// TestSNSCertCacheBoundsFetches: a hit costs nothing, and — the part that was
// missing — a MISS costs nothing the second time either. Without negative caching
// every refused URL was a free outbound TLS request.
func TestSNSCertCacheBoundsFetches(t *testing.T) {
	ctx := context.Background()
	_, certPEM := testSigningCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	ok := &countingTransport{pem: certPEM}
	cache := newCertCache()
	cache.http = &http.Client{Transport: ok}
	for i := 0; i < 5; i++ {
		if _, err := cache.get(ctx, testCertURL); err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}
	if ok.n != 1 {
		t.Fatalf("%d outbound fetches for one certificate, want 1", ok.n)
	}

	bad := &countingTransport{code: http.StatusNotFound}
	neg := newCertCache()
	neg.http = &http.Client{Transport: bad}
	for i := 0; i < 5; i++ {
		if _, err := neg.get(ctx, testCertURL); err == nil {
			t.Fatal("a 404 signing-cert URL was accepted")
		}
	}
	if bad.n != 1 {
		t.Fatalf("%d outbound fetches for one failing URL, want 1 (negative caching)", bad.n)
	}

	// A URL we refuse on shape must cost ZERO fetches, however many times it comes.
	shape := &countingTransport{pem: certPEM}
	sc := newCertCache()
	sc.http = &http.Client{Transport: shape}
	for i := 0; i < 64; i++ {
		if _, err := sc.get(ctx, fmt.Sprintf("%s?n=%d", testCertURL, i)); err == nil {
			t.Fatal("a query-bearing cert URL was accepted")
		}
	}
	if shape.n != 0 {
		t.Fatalf("%d outbound fetches for URLs we refuse outright, want 0", shape.n)
	}
}

// TestSNSCertRevalidatedOnUse: "we trusted it an hour ago" is not a reason to keep
// trusting a signing key that has since expired, and the cache is the only place
// that would.
func TestSNSCertRevalidatedOnUse(t *testing.T) {
	cert, _ := testSigningCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	cache := newCertCache()
	// Cached while it was valid, with plenty of TTL left.
	cache.certs[testCertURL] = cachedCert{cert: cert, expires: time.Now().Add(certTTL)}
	if _, err := cache.get(context.Background(), testCertURL); err == nil {
		t.Fatal("an expired certificate was served from the cache")
	}
}

// TestSNSCertCacheEvictionKeepsWorkingEntry: clearing the whole map on overflow let
// a flood of junk URLs evict the one certificate every real notification needs, so
// each genuine event paid for a fresh fetch. Eviction must drop one entry, not all.
func TestSNSCertCacheEvictionKeepsWorkingEntry(t *testing.T) {
	cert, _ := testSigningCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cache := newCertCache()
	cache.certs[testCertURL] = cachedCert{cert: cert, expires: time.Now().Add(certTTL)}
	now := time.Now()
	for i := 0; i < maxCachedCerts*2; i++ {
		cache.evictLocked(now)
		cache.certs[fmt.Sprintf("https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-%d.pem", i)] =
			cachedCert{err: errors.New("nope"), expires: now.Add(certNegTTL)}
	}
	if len(cache.certs) > maxCachedCerts {
		t.Fatalf("cache holds %d entries, over the %d cap", len(cache.certs), maxCachedCerts)
	}
	if _, ok := cache.certs[testCertURL]; !ok {
		t.Fatal("the long-lived good certificate was evicted by short-lived junk")
	}
}

// testSigningCert makes a self-signed RSA certificate with the given validity
// window, plus its PEM encoding.
func testSigningCert(t *testing.T, notBefore, notAfter time.Time) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "sns.amazonaws.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestSESHookThrottled: the route is public and each accepted message can cost an
// outbound certificate fetch, so it must shed like every other public route.
func TestSESHookThrottled(t *testing.T) {
	s, key := newSESTestServer(t)
	s.sesHookLimit = newRateLimiter(1, time.Minute)
	msg := `{"notificationType":"Bounce","bounce":{"bounceType":"Permanent","bounceSubType":"General",
	  "bouncedRecipients":[{"emailAddress":"first@example.com","status":"5.1.1"}]}}`
	body := signSNS(t, key, &snsMessage{
		Type: "Notification", MessageID: "t1", TopicARN: testTopic, Message: msg,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if w := postSNS(s, body); w.Code != http.StatusOK {
		t.Fatalf("first event = %d, want 200", w.Code)
	}
	second := signSNS(t, key, &snsMessage{
		Type: "Notification", MessageID: "t2", TopicARN: testTopic, Message: msg,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	w := postSNS(s, second)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second event = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("a shed request should say when to come back")
	}
}

// TestSESHookSignatureVersion pins the digest to SHA-256. SignatureVersion is NOT
// covered by the signature, so a caller who can choose it chooses how strong the
// endpoint's trust is — and version 1 is RSA-SHA1 over a string containing text a
// remote mail server wrote, verified by a key shared with every other topic in the
// region. The live topic's SignatureVersion attribute is set to 2, so nothing
// legitimate signs with 1 any more.
func TestSESHookSignatureVersion(t *testing.T) {
	msg := `{"notificationType":"Complaint","complaint":{"complaintFeedbackType":"abuse",
	  "complainedRecipients":[{"emailAddress":"v@example.com"}]}}`
	fresh := func() string { return time.Now().UTC().Format(time.RFC3339) }

	t.Run("version 2 is accepted", func(t *testing.T) {
		s, key := newSESTestServer(t)
		body := signSNSVersion(t, key, &snsMessage{
			Type: "Notification", MessageID: "v2", TopicARN: testTopic, Message: msg, Timestamp: fresh(),
		}, "2")
		if w := postSNS(s, body); w.Code != http.StatusOK {
			t.Fatalf("SignatureVersion 2 = %d, want 200", w.Code)
		}
	})

	// A correctly signed version-1 message is still refused: the signature being
	// valid is not the point, the digest being SHA-1 is.
	t.Run("a genuine version 1 is refused", func(t *testing.T) {
		s, key := newSESTestServer(t)
		body := signSNSVersion(t, key, &snsMessage{
			Type: "Notification", MessageID: "v1", TopicARN: testTopic, Message: msg, Timestamp: fresh(),
		}, "1")
		if w := postSNS(s, body); w.Code != http.StatusForbidden {
			t.Fatalf("SignatureVersion 1 = %d, want 403", w.Code)
		}
	})

	t.Run("an unknown version is refused", func(t *testing.T) {
		s, key := newSESTestServer(t)
		body := signSNSVersion(t, key, &snsMessage{
			Type: "Notification", MessageID: "v3", TopicARN: testTopic, Message: msg, Timestamp: fresh(),
		}, "2")
		// Sign as v2, then relabel: the version is not covered by the signature, so a
		// relabelled message must be refused on the version alone.
		relabelled := strings.Replace(string(body), `"SignatureVersion":"2"`, `"SignatureVersion":"3"`, 1)
		if w := postSNS(s, []byte(relabelled)); w.Code != http.StatusForbidden {
			t.Fatalf("SignatureVersion 3 = %d, want 403", w.Code)
		}
	})

	// Relabelling a v1 signature as v2 must not slip through: the digest the
	// endpoint computes is SHA-256, so the v1 signature cannot verify against it.
	t.Run("a version 1 signature relabelled as version 2 is refused", func(t *testing.T) {
		s, key := newSESTestServer(t)
		body := signSNSVersion(t, key, &snsMessage{
			Type: "Notification", MessageID: "swap", TopicARN: testTopic, Message: msg, Timestamp: fresh(),
		}, "1")
		relabelled := strings.Replace(string(body), `"SignatureVersion":"1"`, `"SignatureVersion":"2"`, 1)
		if w := postSNS(s, []byte(relabelled)); w.Code != http.StatusForbidden {
			t.Fatalf("relabelled v1 signature = %d, want 403", w.Code)
		}
	})
}

// TestSESHookDisabled: with no topic configured the route must not exist at all.
func TestSESHookDisabled(t *testing.T) {
	s, key := newSESTestServer(t)
	s.cfg.SESTopicARN = ""
	body := signSNS(t, key, &snsMessage{
		Type: "Notification", MessageID: "x", TopicARN: testTopic, Message: "{}",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if w := postSNS(s, body); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("hook with no topic configured = %d, want 404/405", w.Code)
	}
}

// TestSESHookRejectsReplay: a valid signature never expires, so a captured
// notification must be refused once it is old. Replaying a bounce is nearly
// idempotent, but it still refreshes last_seen, which alone keeps an address
// suppressed past the point it would have aged out.
func TestSESHookRejectsReplay(t *testing.T) {
	s, key := newSESTestServer(t)
	ctx := context.Background()

	msg := `{"notificationType":"Bounce","bounce":{"bounceType":"Permanent","bounceSubType":"General",
	  "bouncedRecipients":[{"emailAddress":"replayed@example.com","status":"5.1.1"}]}}`
	body := signSNS(t, key, &snsMessage{
		Type: "Notification", MessageID: "old", TopicARN: testTopic, Message: msg,
		Timestamp: time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339),
	})
	if w := postSNS(s, body); w.Code == http.StatusOK {
		t.Fatal("a day-old signed notification was accepted: it can be replayed forever")
	}
	if bad, _, _ := s.store.IsSuppressed(ctx, "replayed@example.com"); bad {
		t.Fatal("a replayed notification wrote a suppression")
	}

	// A message with no timestamp at all is refused rather than trusted.
	noTS := signSNS(t, key, &snsMessage{
		Type: "Notification", MessageID: "nots", TopicARN: testTopic, Message: msg,
	})
	if w := postSNS(s, noTS); w.Code == http.StatusOK {
		t.Fatal("a notification with no timestamp was accepted")
	}
}

// TestSESHookIgnoresNotSpam: RFC 5965 "not-spam" means the recipient moved our
// mail OUT of junk. Treating that as a complaint would permanently suppress
// someone for rescuing us — and a complaint is never pruned or user-clearable.
func TestSESHookIgnoresNotSpam(t *testing.T) {
	s, key := newSESTestServer(t)
	ctx := context.Background()

	msg := `{"notificationType":"Complaint","complaint":{"complaintFeedbackType":"not-spam",
	  "complainedRecipients":[{"emailAddress":"rescuer@example.com"}]}}`
	body := signSNS(t, key, &snsMessage{
		Type: "Notification", MessageID: "ns", TopicARN: testTopic, Message: msg,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if w := postSNS(s, body); w.Code != http.StatusOK {
		t.Fatalf("not-spam report = %d, want 200 (accepted but ignored)", w.Code)
	}
	if bad, reason, _ := s.store.IsSuppressed(ctx, "rescuer@example.com"); bad {
		t.Fatalf("a not-spam report suppressed the recipient (reason %q)", reason)
	}

	// A real complaint on the same endpoint still suppresses.
	real := `{"notificationType":"Complaint","complaint":{"complaintFeedbackType":"abuse",
	  "complainedRecipients":[{"emailAddress":"angry@example.com"}]}}`
	body = signSNS(t, key, &snsMessage{
		Type: "Notification", MessageID: "ab", TopicARN: testTopic, Message: real,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if w := postSNS(s, body); w.Code != http.StatusOK {
		t.Fatalf("abuse complaint = %d, want 200", w.Code)
	}
	if bad, reason, _ := s.store.IsSuppressed(ctx, "angry@example.com"); !bad || reason != store.SuppressComplaint {
		t.Fatalf("real complaint suppressed=%v reason=%q, want true/complaint", bad, reason)
	}
}
