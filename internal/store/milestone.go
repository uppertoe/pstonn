package store

import "context"

// Milestones returns the once-ever markers recorded for an account, keyed by
// the checklist line they satisfy. Unlike the change log these are never pruned.
func (s *Store) Milestones(ctx context.Context, owner string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key FROM account_milestone WHERE owner = ?`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, rows.Err()
}

// MarkMilestone records that the account has done the thing once. Idempotent.
func (s *Store) MarkMilestone(ctx context.Context, owner, key string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO account_milestone (owner, key, at) VALUES (?, ?, ?)`, owner, key, nowUTC())
	return err
}
