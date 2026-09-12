package store

import "context"

// Milestone is a once-ever fact about an account, recorded the first time the
// action succeeds and never pruned: the "still to try" lines read these. The
// set is deliberately small and closed; it is product education, not an event
// system. Unlike the change log these rows are removed only with the account.
type Milestone string

const (
	MilestoneRoster        Milestone = "roster"         // a rego on a day of the weekly roster
	MilestoneBooking       Milestone = "booking"        // a one-off booking made
	MilestoneWeeks         Milestone = "weeks"          // a second roster week added
	MilestoneRego          Milestone = "rego"           // a rego saved
	MilestoneRegoEmail     Milestone = "rego-email"     // an email attached to a rego
	MilestoneVisitorQR     Milestone = "visitor-qr"     // a visitor QR shown
	MilestoneGuestPass     Milestone = "guest-pass"     // a guest pass sent
	MilestonePrintedQR     Milestone = "printed-qr"     // a printed QR created
	MilestonePermitName    Milestone = "permit-name"    // a permit given a name
	MilestoneHouseholdName Milestone = "household-name" // the household named for visitors
	MilestoneShared        Milestone = "shared"         // someone given shared access
)

// MilestoneNotify is per person rather than per account: notification settings
// belong to the signed-in member, not the household.
func MilestoneNotify(user string) Milestone { return Milestone("notify:" + user) }

// Milestones returns the account's recorded milestones.
func (s *Store) Milestones(ctx context.Context, owner string) (map[Milestone]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key FROM account_milestone WHERE owner = ?`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[Milestone]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out[Milestone(k)] = true
	}
	return out, rows.Err()
}

// MarkMilestone records that the account has done the thing once. Idempotent.
func (s *Store) MarkMilestone(ctx context.Context, owner string, m Milestone) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO account_milestone (owner, key, at) VALUES (?, ?, ?)`, owner, string(m), nowUTC())
	return err
}
