package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// Unsubscribe links are stateless: the token is an HMAC of the address under a
// server-held key, so any address can be verified without storing a row per
// recipient. That matters because most recipients of our mail have no account at
// all — a guest sent a pass link, a driver whose car came off a permit — and they
// are exactly the people entitled to make us stop.
//
// The key is derived from the app's at-rest key. If that ever rotates, existing
// unsubscribe links stop verifying; the footer link in an old email would fail
// closed (refuse) rather than act on the wrong address, and the recipient can
// still reply or use the mailto form.
const unsubKeyContext = "pstonn-unsubscribe-v1"

// DeriveUnsubKey makes the unsubscribe-signing key from the at-rest key. Kept
// separate from the sealing key so a token can never be confused with ciphertext.
func DeriveUnsubKey(dataKey []byte) []byte {
	h := sha256.Sum256(append([]byte(unsubKeyContext+"|"), dataKey...))
	return h[:]
}

// unsubToken is the tag proving a link was issued by us for this address.
func unsubToken(key []byte, address string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(address))))
	// 16 bytes is ample for a capability that only ever stops mail to one address.
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// VerifyUnsubToken reports whether tok is the valid tag for address.
func VerifyUnsubToken(key []byte, address, tok string) bool {
	if len(key) == 0 || address == "" || tok == "" {
		return false
	}
	return hmac.Equal([]byte(unsubToken(key, address)), []byte(tok))
}

// UnsubscribeURL is the link placed in every user-facing email. The address is
// carried in the path (base64url) so the endpoint knows who to act on without
// storing anything; the token stops it being used to unsubscribe someone else.
func (s *Service) UnsubscribeURL(address string) string {
	if s.appURL == "" || len(s.unsubKey) == 0 || address == "" {
		return ""
	}
	a := base64.RawURLEncoding.EncodeToString([]byte(strings.ToLower(strings.TrimSpace(address))))
	return s.appURL + "/u/" + a + "/" + unsubToken(s.unsubKey, address)
}

// DecodeUnsubAddress reverses the path encoding.
func DecodeUnsubAddress(encoded string) (string, bool) {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	a := strings.ToLower(strings.TrimSpace(string(b)))
	if a == "" || !strings.Contains(a, "@") || strings.ContainsAny(a, "\r\n") {
		return "", false
	}
	return a, true
}
