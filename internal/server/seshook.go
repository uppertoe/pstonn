package server

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // AWS SNS SignatureVersion 1 specifies SHA1WithRSA; not our choice.
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

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
		log.Printf("ses hook: refusing message for unexpected topic %q", m.TopicARN)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := verifySNSSignature(r.Context(), s.snsCert, &m); err != nil {
		log.Printf("ses hook: signature verification failed: %v", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	switch m.Type {
	case "SubscriptionConfirmation":
		// Confirm by fetching the URL SNS supplied. It is signature-verified above
		// and host-checked here, so this cannot be pointed at an arbitrary target.
		if err := confirmSNSSubscription(r.Context(), m.SubscribeURL); err != nil {
			log.Printf("ses hook: subscription confirmation failed: %v", err)
			http.Error(w, "confirmation failed", http.StatusBadGateway)
			return
		}
		log.Printf("ses hook: confirmed SNS subscription for topic %s", m.TopicARN)
	case "Notification":
		s.handleSESEvent(r, m.Message)
	case "UnsubscribeConfirmation":
		// Someone unsubscribed our endpoint. That silently disables bounce handling,
		// so make it loud rather than letting the app drift back to no feedback.
		log.Printf("ses hook: WARNING our SNS subscription was cancelled for %s", m.TopicARN)
	default:
		log.Printf("ses hook: ignoring message type %q", m.Type)
	}
	w.WriteHeader(http.StatusOK)
}

// handleSESEvent records suppressions from one SES notification. Only PERMANENT
// bounces and complaints suppress: a transient bounce (full mailbox, greylisting)
// is exactly what the outbox's retry is for, and suppressing on it would mute a
// user over a temporary condition.
func (s *Server) handleSESEvent(r *http.Request, raw string) {
	var ev sesEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		log.Printf("ses hook: unparseable SES event: %v", err)
		return
	}
	kind := ev.NotificationType
	if kind == "" {
		kind = ev.EventType
	}
	ctx := r.Context()
	switch strings.ToLower(kind) {
	case "bounce":
		if !strings.EqualFold(ev.Bounce.BounceType, "Permanent") {
			log.Printf("ses hook: %s/%s bounce — not suppressing (retryable)", ev.Bounce.BounceType, ev.Bounce.BounceSubType)
			return
		}
		for _, rcpt := range ev.Bounce.BouncedRecipients {
			detail := strings.TrimSpace(rcpt.Status + " " + rcpt.DiagnosticCode)
			if detail == "" {
				detail = ev.Bounce.BounceSubType
			}
			if err := s.store.SuppressAddress(ctx, rcpt.EmailAddress, store.SuppressBounce, detail); err != nil {
				log.Printf("ses hook: suppress %s: %v", rcpt.EmailAddress, err)
				continue
			}
			log.Printf("ses hook: suppressed %s (permanent bounce: %s)", rcpt.EmailAddress, detail)
		}
	case "complaint":
		for _, rcpt := range ev.Complaint.ComplainedRecipients {
			if err := s.store.SuppressAddress(ctx, rcpt.EmailAddress, store.SuppressComplaint, ev.Complaint.ComplaintFeedbackType); err != nil {
				log.Printf("ses hook: suppress %s: %v", rcpt.EmailAddress, err)
				continue
			}
			log.Printf("ses hook: suppressed %s (spam complaint)", rcpt.EmailAddress)
		}
	case "delivery":
		// Nothing to do; subscribing to deliveries is optional and harmless.
	default:
		log.Printf("ses hook: ignoring SES event %q", kind)
	}
}

// certCache memoises fetched SNS signing certificates. AWS rotates them rarely,
// and re-fetching per notification would make a bounce storm into an outbound
// request storm.
type certCache struct {
	mu    sync.Mutex
	certs map[string]*x509.Certificate
	http  *http.Client
}

func newCertCache() *certCache {
	return &certCache{
		certs: map[string]*x509.Certificate{},
		http:  &http.Client{Timeout: 10 * time.Second},
	}
}

// errUntrustedCertHost rejects a signing certificate URL that is not an AWS
// host. Without this check the signature proves nothing: an attacker would sign
// a forged notification with their own key and point us at their own cert.
var errUntrustedCertHost = errors.New("signing certificate URL is not an AWS host")

func (c *certCache) get(ctx context.Context, rawURL string) (*x509.Certificate, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || !isAWSHost(u.Host) {
		return nil, fmt.Errorf("%w: %q", errUntrustedCertHost, rawURL)
	}
	c.mu.Lock()
	if cert, ok := c.certs[rawURL]; ok {
		c.mu.Unlock()
		return cert, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
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
	c.mu.Lock()
	c.certs[rawURL] = cert
	c.mu.Unlock()
	return cert, nil
}

// isAWSHost reports whether a host belongs to Amazon. Matched on the registrable
// suffix with a leading dot so "evil-amazonaws.com" and "amazonaws.com.evil.tld"
// are both rejected.
func isAWSHost(host string) bool {
	h := strings.ToLower(host)
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i] // strip any port
	}
	return strings.HasSuffix(h, ".amazonaws.com")
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

// verifySNSSignature checks the message really came from the SNS topic it claims.
func verifySNSSignature(ctx context.Context, cache *certCache, m *snsMessage) error {
	if m.Signature == "" || m.SigningCertURL == "" {
		return errors.New("message is unsigned")
	}
	var hash crypto.Hash
	switch m.SignatureVersion {
	case "1":
		hash = crypto.SHA1
	case "2":
		hash = crypto.SHA256
	default:
		return fmt.Errorf("unsupported SignatureVersion %q", m.SignatureVersion)
	}
	cert, err := cache.get(ctx, m.SigningCertURL)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("signing certificate is not RSA")
	}
	var sb strings.Builder
	for _, f := range snsSigningFields(m) {
		sb.WriteString(f.key)
		sb.WriteString("\n")
		sb.WriteString(f.val)
		sb.WriteString("\n")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("signature is not base64: %w", err)
	}
	var digest []byte
	if hash == crypto.SHA1 {
		sum := sha1.Sum([]byte(sb.String())) //nolint:gosec // AWS SignatureVersion 1 mandates SHA1.
		digest = sum[:]
	} else {
		sum := sha256.Sum256([]byte(sb.String()))
		digest = sum[:]
	}
	return rsa.VerifyPKCS1v15(pub, hash, digest, sig)
}

// confirmSNSSubscription completes the SNS handshake by fetching SubscribeURL.
// The URL is host-checked again here (defence in depth: the signature check
// already covers it, but this function is what actually makes the request).
func confirmSNSSubscription(ctx context.Context, subscribeURL string) error {
	u, err := url.Parse(subscribeURL)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || !isAWSHost(u.Host) {
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
