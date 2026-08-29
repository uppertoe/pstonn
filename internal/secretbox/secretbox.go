// Package secretbox provides authenticated encryption for data at rest
// (AES-256-GCM). It is used to seal the tenant session cookie (and cached
// access token) before they are written to SQLite, so a leaked database file
// does not expose usable credentials.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Box seals and opens secrets with a single AES-256 key.
type Box struct {
	aead cipher.AEAD
}

// New builds a Box from a 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secretbox: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// SealCtx encrypts plaintext, binding the result to context, and returns a base64
// string of nonce||ciphertext. Only OpenCtx with the SAME context can open it.
//
// The context is what makes a ciphertext mean something. One key seals four
// different secrets here — the tenant session cookie, its access token, the
// tenant PASSWORD, and guest-pass tokens — and with no binding they are freely
// interchangeable: a blob is just "something this key encrypted". Anyone able to
// write a row could move one household's password ciphertext into another's
// guest_token.token_sealed, and the door-QR page would then decrypt and DISPLAY it,
// because that page's whole job is to reprint the token it finds there. Encryption
// was providing confidentiality with no notion of whose secret this is or what it
// is for. Binding (owner, purpose) into the AAD makes every such move fail to open.
//
// context is authenticated, not encrypted: it must not itself be secret, and it must
// be reproducible at open time from the row being read (never from user input).
func (b *Box) SealCtx(context, plaintext string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := b.aead.Seal(nonce, nonce, []byte(plaintext), []byte(context))
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenCtx reverses SealCtx. legacy reports that the ciphertext predates context
// binding and was opened unbound, so a caller that is about to write anyway can
// re-seal it bound.
//
// The fallback exists because production databases hold blobs sealed by older
// builds, and refusing them outright would unlink every household at once — a
// self-inflicted outage far worse than the (write-primitive-gated) weakness it
// closes. Those blobs remain movable until re-sealed, so this is a migration
// window, not the end state: tenant cookies and tokens re-seal on every keep-warm
// pass, and the rest re-seal on their next write.
func (b *Box) OpenCtx(context, encoded string) (plaintext string, legacy bool, err error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false, err
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return "", false, errors.New("secretbox: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	if pt, err := b.aead.Open(nil, nonce, ct, []byte(context)); err == nil {
		return string(pt), false, nil
	}
	// Bound open failed. Either it is an old unbound blob, or it is a blob from
	// another context — and those two are indistinguishable here, which is precisely
	// why the fallback has to go away once deployments have turned over.
	pt, err := b.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", false, err
	}
	return string(pt), true, nil
}

// Seal encrypts plaintext with NO context binding.
//
// Reserved for the /status roster payload, which is decrypted by a separate process
// (the outage watchdog holding ROSTER_KEY). That is a wire format between two
// programs, so it cannot gain an AAD without changing the watchdog too. Everything
// stored in a database row must use SealCtx instead — see its comment for why.
func (b *Box) Seal(plaintext string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := b.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal. Same restriction: unbound, so roster-payload use only.
func (b *Box) Open(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("secretbox: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	plaintext, err := b.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
