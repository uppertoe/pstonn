package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // matching AWS SignatureVersion 1
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// signSNS builds a signed SNS envelope the way AWS would, so the handler's
// verification path is exercised for real rather than stubbed out.
func signSNS(t *testing.T, key *rsa.PrivateKey, m *snsMessage) []byte {
	t.Helper()
	m.SignatureVersion = "1"
	m.SigningCertURL = "https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-test.pem"
	var sb strings.Builder
	for _, f := range snsSigningFields(m) {
		sb.WriteString(f.key)
		sb.WriteString("\n")
		sb.WriteString(f.val)
		sb.WriteString("\n")
	}
	sum := sha1.Sum([]byte(sb.String())) //nolint:gosec // AWS SignatureVersion 1
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum[:])
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
	cache.certs["https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-test.pem"] = cert

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
		"https://evil.example.com/cert.pem",
		"https://sns.amazonaws.com.evil.tld/cert.pem",
		"https://evil-amazonaws.com/cert.pem",
		"http://sns.ap-southeast-2.amazonaws.com/cert.pem", // not https
		// The dangerous near-miss: anyone with an AWS account can serve arbitrary
		// files from these hosts, so accepting them means accepting an
		// attacker-supplied signing key. "Ends with .amazonaws.com" is NOT the
		// property we need — only SNS's own regional endpoints are.
		"https://my-bucket.s3.amazonaws.com/cert.pem",
		"https://s3.ap-southeast-2.amazonaws.com/my-bucket/cert.pem",
		"https://sns.evil.com.amazonaws.com/cert.pem", // extra label in the region slot
		"https://notsns.ap-southeast-2.amazonaws.com/cert.pem",
	} {
		if _, err := newCertCache().get(context.Background(), host); err == nil {
			t.Fatalf("cert URL %q was accepted, want rejection", host)
		}
	}
	// Genuine SNS endpoints must still pass the host check. They fail later (no
	// server is listening), so assert on WHICH error came back.
	for _, host := range []string{
		"https://sns.ap-southeast-2.amazonaws.com/cert.pem",
		"https://sns.us-east-1.amazonaws.com/cert.pem",
		"https://sns.cn-north-1.amazonaws.com.cn/cert.pem",
	} {
		_, err := newCertCache().get(context.Background(), host)
		if errors.Is(err, errUntrustedCertHost) {
			t.Fatalf("cert URL %q was rejected as an untrusted host, want it allowed", host)
		}
	}
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
