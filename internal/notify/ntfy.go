package notify

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (s *Service) sendNtfy(ctx context.Context, topic, title, body, priority, tags string) error {
	return s.sendNtfyHeaders(ctx, topic, title, body, priority, tags, nil)
}

// sendNtfyHeaders is sendNtfy with extra publish headers (Actions, Click, …).
func (s *Service) sendNtfyHeaders(ctx context.Context, topic, title, body, priority, tags string, extra map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.ntfyBase+"/"+topic, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", priority)
	req.Header.Set("Tags", tags)
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	if s.ntfyToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.ntfyToken)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Drain so the keep-alive connection is reusable.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy returned status %d", resp.StatusCode)
	}
	return nil
}

// RandomTopic returns an unguessable ntfy topic for a new user (topics are the
// only access control on a public ntfy server, so they must not be guessable).
// RandomTopic returns an unguessable but easy-to-type ntfy topic. An ntfy topic
// is a shared secret the user types by hand into the phone app, so we favour a
// pronounceable, unambiguous form (alternating consonant/vowel syllables in
// hyphen-separated groups, no look-alike letters like l/1/o/0) over raw hex.
// Four four-letter groups give roughly 52 bits of entropy: ample for what is a
// low-stakes, rate-limited read capability, while staying quick to key in.
func RandomTopic() string {
	const cons = "bcdfghjkmnpqrstvwxz" // consonants, minus ambiguous l and y
	const vows = "aeiou"
	b := make([]byte, 16)
	_, _ = crand.Read(b)
	var sb strings.Builder
	sb.WriteString("pstonn")
	for i := 0; i < len(b); i++ {
		if i%4 == 0 {
			sb.WriteByte('-')
		}
		if i%2 == 0 {
			sb.WriteByte(cons[int(b[i])%len(cons)])
		} else {
			sb.WriteByte(vows[int(b[i])%len(vows)])
		}
	}
	return sb.String()
}

// ErrNoPush: a push-only send was asked for by someone whose push channel is off.
var ErrNoPush = errors.New("notify: push notifications are not enabled")
