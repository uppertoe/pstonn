package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ---- OAuth PKCE state ----

// OAuthState is a stored, single-use authorization request (state → PKCE
// verifier + nonce), shared by the app-login and tenant-link flows.
type OAuthState struct {
	Verifier string
	Nonce    string
	Kind     string
}

// oauthStateTTL bounds how long an authorization request stays redeemable. A
// login round-trip takes seconds; anything older is an abandoned attempt or a
// captured state being replayed.
const oauthStateTTL = 15 * time.Minute

func (s *Store) PutOAuthState(ctx context.Context, state, verifier, nonce, kind string) error {
	// Rows are written by unauthenticated visitors and only deleted on a
	// completed login, so sweep expired ones here or the table grows without
	// bound under bot traffic. Best-effort: a sweep failure must not block login.
	cutoff := time.Now().UTC().Add(-oauthStateTTL).Format(time.RFC3339)
	_, _ = s.db.ExecContext(ctx, `DELETE FROM oauth_state WHERE created_at < ?`, cutoff)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oauth_state (state, verifier, nonce, kind, created_at) VALUES (?, ?, ?, ?, ?)`,
		state, verifier, nonce, kind, nowUTC())
	return err
}

// TakeOAuthState returns and deletes the stored state (single use). The delete
// and read are one atomic statement so two concurrent presentations of the same
// state cannot both succeed, and a state older than oauthStateTTL is treated as
// never stored.
func (s *Store) TakeOAuthState(ctx context.Context, state string) (OAuthState, error) {
	var os OAuthState
	cutoff := time.Now().UTC().Add(-oauthStateTTL).Format(time.RFC3339)
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM oauth_state WHERE state = ? AND created_at >= ? RETURNING verifier, nonce, kind`,
		state, cutoff).
		Scan(&os.Verifier, &os.Nonce, &os.Kind)
	if errors.Is(err, sql.ErrNoRows) {
		return os, ErrNotFound
	}
	return os, err
}
