package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// Unsubscribe links are stateless: the token is an HMAC over the address (plus a
// version tag and an expiry) under a server-held key, so any address can be
// verified without storing a row per recipient. That matters because most
// recipients of our mail have no account at all — a guest sent a pass link, a
// driver whose car came off a permit — and they are exactly the people entitled
// to make us stop.
//
// The key is derived from the app's at-rest key. If that ever rotates, existing
// unsubscribe links stop verifying; the footer link in an old email would fail
// closed (refuse) rather than act on the wrong address, and the recipient can
// still reply or use the mailto form.
const unsubKeyContext = "pstonn-unsubscribe-v1"

// minDataKeyLen is the shortest at-rest key we will derive an unsubscribe key
// from. It matches the 32 bytes config already insists on for
// DATA_ENCRYPTION_KEY, so the only value that ever falls short is the empty one.
const minDataKeyLen = 32

// unsubKeyLen is the length of a derived key. Callers check against this rather
// than against zero: a short key is not a key, and treating one as usable is how
// an unsubscribe link becomes forgeable.
const unsubKeyLen = sha256.Size

// DeriveUnsubKey makes the unsubscribe-signing key from the at-rest key. Kept
// separate from the sealing key so a token can never be confused with ciphertext.
//
// A key shorter than minDataKeyLen yields NO key at all, loudly. Hashing a short
// or empty input produced a perfectly well-formed 32-byte key that anybody could
// recompute — SHA-256("pstonn-unsubscribe-v1|") is a world-known constant — so a
// deployment with no DATA_ENCRYPTION_KEY was handing out unsubscribe tokens that
// anyone could forge for any address, and forging one permanently suppresses that
// address's mail. Returning nil instead means UnsubscribeURL emits no link and
// VerifyUnsubToken refuses everything: the dev path still starts, just without
// unsubscribe links rather than with forgeable ones.
func DeriveUnsubKey(dataKey []byte) []byte {
	if len(dataKey) < minDataKeyLen {
		alog.Warnf("DATA_ENCRYPTION_KEY is unset or too short (%d bytes, need %d), "+
			"so unsubscribe links are DISABLED. A key derived from a short secret is guessable, "+
			"which would let anyone silence any address's notifications. Outgoing mail will carry "+
			"no List-Unsubscribe header until a real key is set.", len(dataKey), minDataKeyLen)
		return nil
	}
	h := sha256.Sum256(append([]byte(unsubKeyContext+"|"), dataKey...))
	return h[:]
}

// unsubTokenVersion tags the current token format, and is itself part of the
// SIGNED material. Without it a token minted under one policy could be re-read
// under another (a longer life, a different field order) and still verify, which
// is the trap the address-only v1 token fell into.
const unsubTokenVersion = "2"

// unsubTokenLife bounds how long a freshly minted link stays usable. The token
// is a bearer capability that travels in a URL path, so it lands in every proxy
// access log the mail passes through and in every archive of the message — an
// eternal one is a permanent, unrevocable ability to silence that address.
//
// A year is deliberately generous. A stale token only ever matters for an OLD
// email: anyone still receiving mail from us has a fresh link in the most recent
// message, and anyone who stopped hearing from us has nothing to unsubscribe
// from. It also gives a key rotation a bounded tail rather than an endless one.
const unsubTokenLife = 365 * 24 * time.Hour

// unsubLegacySunset is when v1 tokens (an address-only MAC, no version, no
// expiry) stop verifying. They are still accepted until then, on purpose: they
// are already sitting in mail we have sent, and Gmail's and Yahoo's one-click
// button uses exactly this URL. A button that fails does not make the recipient
// shrug — it makes them press "report spam" instead, and a complaint costs the
// whole sending domain's reputation while an unsubscribe costs one address. So
// the eternal tokens get a few months to age out of live inboxes and then fail
// closed with the same neutral "isn't valid or has expired" message.
var unsubLegacySunset = time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)

// normaliseUnsubAddress is how an address is spelled inside the signed material,
// so the same mailbox typed in any case verifies against its own token.
func normaliseUnsubAddress(address string) string {
	return strings.ToLower(strings.TrimSpace(address))
}

// unsubToken is the tag proving a link was issued by us, for this address, under
// this version, until this expiry.
func unsubToken(key []byte, address string, expiry time.Time) string {
	exp := strconv.FormatInt(expiry.Unix(), 36)
	return unsubTokenVersion + "." + exp + "." + unsubMAC(key, unsubTokenVersion, exp, address)
}

// unsubMAC signs version, expiry and address together. The fields are delimited
// so no pair of them can be re-cut into a different pair that signs the same
// bytes, and the address goes last because it is the only field whose alphabet
// we do not control.
func unsubMAC(key []byte, version, exp, address string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(version + "|" + exp + "|" + normaliseUnsubAddress(address)))
	// 16 bytes is ample for a capability that only ever stops mail to one address.
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// legacyUnsubMAC is the retired v1 tag: the address alone, with nothing bounding
// its life. Kept only to honour links already in people's inboxes until
// unsubLegacySunset.
func legacyUnsubMAC(key []byte, address string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(normaliseUnsubAddress(address)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// VerifyUnsubToken reports whether tok authorises unsubscribing address.
func VerifyUnsubToken(key []byte, address, tok string) bool {
	return verifyUnsubTokenAt(key, address, tok, time.Now())
}

// verifyUnsubTokenAt is VerifyUnsubToken with the clock injected, so expiry and
// the legacy sunset are testable without waiting a year.
func verifyUnsubTokenAt(key []byte, address, tok string, now time.Time) bool {
	// A key that is not a full derived key is not usable: DeriveUnsubKey returns nil
	// when the at-rest key is missing, and every token must fail closed in that
	// deployment rather than being verifiable against a guessable key.
	if len(key) < unsubKeyLen || address == "" || tok == "" {
		return false
	}
	version, exp, mac, ok := splitUnsubToken(tok)
	if !ok {
		// No version marker: a v1 token, which carries no expiry of its own. Its life
		// is the sunset date instead.
		if now.Before(unsubLegacySunset) {
			return hmac.Equal([]byte(legacyUnsubMAC(key, address)), []byte(tok))
		}
		return false
	}
	if version != unsubTokenVersion {
		return false
	}
	// The expiry is public (it is written in the token), so checking it before the
	// MAC leaks nothing and saves the hash on an obviously dead link.
	secs, err := strconv.ParseInt(exp, 36, 64)
	if err != nil || now.After(time.Unix(secs, 0)) {
		return false
	}
	return hmac.Equal([]byte(unsubMAC(key, version, exp, address)), []byte(mac))
}

// splitUnsubToken splits a versioned token into its three parts. A token with no
// dots is a v1 token (its MAC alphabet is base64url, which has none), which is
// how the two formats stay unambiguous.
func splitUnsubToken(tok string) (version, exp, mac string, ok bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// UnsubscribeURL is the link placed in every user-facing email. The address is
// carried in the path (base64url) so the endpoint knows who to act on without
// storing anything; the token stops it being used to unsubscribe someone else.
// Empty when there is no usable signing key — no link at all is far better than
// a forgeable one.
func (s *Service) UnsubscribeURL(address string) string {
	if s.appURL == "" || len(s.unsubKey) < unsubKeyLen || address == "" {
		return ""
	}
	a := base64.RawURLEncoding.EncodeToString([]byte(normaliseUnsubAddress(address)))
	return s.appURL + "/u/" + a + "/" + unsubToken(s.unsubKey, address, time.Now().Add(unsubTokenLife))
}

// DecodeUnsubAddress reverses the path encoding.
func DecodeUnsubAddress(encoded string) (string, bool) {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	a := normaliseUnsubAddress(string(b))
	if a == "" || !strings.Contains(a, "@") || strings.ContainsAny(a, "\r\n") {
		return "", false
	}
	return a, true
}
