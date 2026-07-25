package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ---- Terms consent ----

// Consent is one recorded acceptance of the terms.
type Consent struct {
	Owner    string
	Version  string
	Hash     string
	AgreedAt time.Time
}

// RecordConsent appends an acceptance of the given terms version/hash.
func (s *Store) RecordConsent(ctx context.Context, owner, version, hash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO consent (owner, version, hash, agreed_at) VALUES (?, ?, ?, ?)`,
		owner, version, hash, nowUTC())
	return err
}

// LatestConsent returns the user's most recent acceptance, or ErrNotFound.
func (s *Store) LatestConsent(ctx context.Context, owner string) (Consent, error) {
	var c Consent
	var at string
	err := s.db.QueryRowContext(ctx,
		`SELECT owner, version, hash, agreed_at FROM consent WHERE owner = ? ORDER BY id DESC LIMIT 1`, owner).
		Scan(&c.Owner, &c.Version, &c.Hash, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.AgreedAt, _ = time.Parse(time.RFC3339, at)
	return c, nil
}
