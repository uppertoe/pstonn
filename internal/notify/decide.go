package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"strconv"
	"time"
)

// Guest-request decide links let a household member approve or decline a
// printed-QR request straight from the notification email, with no sign-in.
// The trust argument: sign-in IS an emailed code, so the inbox is already the
// root of trust for the whole account — a link in that same inbox that can
// decide one pending request grants strictly less than the code does. The
// token is stateless like the unsubscribe token (an HMAC over request id +
// recipient + expiry under a derived key); single-use comes from the request
// row itself, because a decision only ever lands on a row still 'pending'.
//
// The capability goes in EMAIL ONLY, never in the ntfy push: ntfy topics are
// readable by anyone who learns the topic name (that is the design), and today
// a leaked topic only leaks information — it must not start granting actions.
const decideKeyContext = "pstonn-guest-decide-v1"

// decideTokenVersion tags the token format and is part of the signed material,
// for the same re-reading reason as the unsubscribe token's version tag.
const decideTokenVersion = "1"

// decideTokenLife bounds the link. The request itself expires within the hour,
// so after that the token can only ever open the "already decided/expired"
// page — a read of one request's outcome. Two days keeps a late click legible
// (the reader learns what happened) without leaving a long-lived bearer URL in
// mail archives.
const decideTokenLife = 48 * time.Hour

// DeriveDecideKey makes the decide-link signing key from the at-rest key. Same
// fail-closed contract as DeriveUnsubKey: a short or missing at-rest key yields
// NO key — emails then simply carry no decide link (the notification still
// points at the signed-in approvals page), rather than a forgeable one that
// would let anyone approve a stranger's plate onto the permit.
func DeriveDecideKey(dataKey []byte) []byte {
	if len(dataKey) < minDataKeyLen {
		log.Printf("WARNING: DATA_ENCRYPTION_KEY is unset or too short (%d bytes, need %d), "+
			"so no-sign-in approve/decline links are DISABLED. A key derived from a short secret "+
			"is guessable, which would let anyone decide guest requests. Request emails will link "+
			"to the signed-in approvals page only until a real key is set.", len(dataKey), minDataKeyLen)
		return nil
	}
	h := sha256.Sum256(append([]byte(decideKeyContext+"|"), dataKey...))
	return h[:]
}

// decideToken proves a link was issued by us, for this request, to this
// recipient, until this expiry.
func decideToken(key []byte, reqID int64, address string, expiry time.Time) string {
	exp := strconv.FormatInt(expiry.Unix(), 36)
	return decideTokenVersion + "." + exp + "." + decideMAC(key, decideTokenVersion, exp, reqID, address)
}

// decideMAC signs version, expiry, request id and recipient together, delimited
// so no field can bleed into its neighbour; the address goes last because it is
// the only field whose alphabet we do not control.
func decideMAC(key []byte, version, exp string, reqID int64, address string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(version + "|" + exp + "|" + strconv.FormatInt(reqID, 10) + "|" + normaliseUnsubAddress(address)))
	mac.Write([]byte{0}) // domain separation from any future same-shape token
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// VerifyDecideToken reports whether tok authorises address to decide request reqID.
func VerifyDecideToken(key []byte, reqID int64, address, tok string) bool {
	return verifyDecideTokenAt(key, reqID, address, tok, time.Now())
}

// verifyDecideTokenAt is VerifyDecideToken with the clock injected for tests.
func verifyDecideTokenAt(key []byte, reqID int64, address, tok string, now time.Time) bool {
	if len(key) < unsubKeyLen || address == "" || tok == "" || reqID <= 0 {
		return false
	}
	version, exp, mac, ok := splitUnsubToken(tok)
	if !ok || version != decideTokenVersion {
		return false
	}
	expUnix, err := strconv.ParseInt(exp, 36, 64)
	if err != nil || now.After(time.Unix(expUnix, 0)) {
		return false
	}
	return hmac.Equal([]byte(decideMAC(key, version, exp, reqID, address)), []byte(mac))
}

// GuestDecideURL is the no-sign-in approve/decline link for one recipient and
// one request. Empty when there is no usable signing key or public base URL —
// the email then simply omits the line.
func (s *Service) GuestDecideURL(reqID int64, address string) string {
	if s.appURL == "" || len(s.decideKey) < unsubKeyLen || address == "" || reqID <= 0 {
		return ""
	}
	a := base64.RawURLEncoding.EncodeToString([]byte(normaliseUnsubAddress(address)))
	return s.appURL + "/r/" + strconv.FormatInt(reqID, 10) + "/" + a + "/" +
		decideToken(s.decideKey, reqID, address, time.Now().Add(decideTokenLife))
}
