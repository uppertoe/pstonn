package store

import "context"

// HouseholdName is what visitors see in place of the holder's email on guest
// links and QR pages. Empty means the pages name only the permit.
func (s *Store) HouseholdName(ctx context.Context, owner string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT household_name FROM account_flags WHERE owner = ?), '')`, owner).Scan(&v)
	return v, err
}

// SetHouseholdName stores the visitor-facing name; empty clears it.
func (s *Store) SetHouseholdName(ctx context.Context, owner, name string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO account_flags (owner, household_name) VALUES (?, ?)
ON CONFLICT(owner) DO UPDATE SET household_name = excluded.household_name`, owner, name)
	return err
}
