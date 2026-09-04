package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// GuestRequest is a visitor's pending/approved/denied request to use a
// printed-QR permit.
type GuestRequest struct {
	ID          int64
	GrantID     int64
	Owner       string
	PermitID    int64
	Plate       string
	State       string // the plate's registration state code as the visitor chose it ("" = the tenant's home state)
	Status      string // pending | approved | denied
	RequestedAt time.Time
	DecidedAt   time.Time // when the holder approved/denied ("" while pending)
	DecidedBy   string    // which account member decided ("" while pending / expired unanswered)
	Until       string    // human "until …" text, set on approval
	UntilTS     time.Time // when the approved window ends (zero while pending/denied)
}

// CreateGuestRequest records a pending request from a printed-QR scan. nonce is a
// per-request secret the visitor keeps, so they can poll its status without being
// able to read other requests.
// CreateGuestRequest records a pending printed-QR request, or reuses an existing
// still-pending one for the same grant+plate so a double-scan/submit doesn't stack
// duplicate requests (and duplicate approval nudges). Returns the request id, the
// effective nonce (the reused row's, so its status page keeps working), and
// whether a NEW request was created (the caller only notifies when it did).
// ErrGuestRequestLimit means the grant already has the maximum number of open
// pending requests. The door QR is deliberately public, so without a cap anyone
// who has seen the poster could flood the holder's approval queue (and their
// notification channels) with junk plates.
//
// On the reuse path the returned nonce is the EXISTING row's poll secret, and the
// store has no way to tell who is asking. It must therefore only ever be
// disclosed to a requester who can already present it — two different visitors
// can type the same plate, and handing the second one the first one's nonce lets
// them read a stranger's request. guestRequest gates it on the browser's own
// request cookie for exactly this reason.
var ErrGuestRequestLimit = errors.New("store: too many pending requests for this grant")

// maxPendingGuestRequests bounds open pending rows per grant.
const maxPendingGuestRequests = 5

// guestReqReserved is how many of those slots are held back for a scanner the
// request handler has not heard from recently.
//
// The cap alone is a shared resource on a PUBLIC surface: five posts with
// distinct plates fill it from one phone, and because pending rows only age out
// after an hour (on a 15-minute sweep) that bricks the door QR for the next
// visitor for 60-75 minutes, repeatably. Refusing a scanner who has already
// asked once the queue reaches the reserved tail means one phone can occupy at
// most maxPendingGuestRequests-guestReqReserved slots, so a genuine visitor —
// whom we have not heard from — always has somewhere to land. Below the tail
// nobody is throttled at all, so the ordinary case (an empty queue, a visitor
// mistyping their plate twice) is untouched.
const guestReqReserved = 2

// PendingGuestRequestsInReserve reports whether a grant's pending queue has grown
// into the slots reserved for a scanner we have not heard from (see
// guestReqReserved). The handler consults it before creating a request so the
// reserve policy lives next to the cap it partitions.
func (s *Store) PendingGuestRequestsInReserve(ctx context.Context, grantID int64) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM guest_request WHERE grant_id = ? AND status = 'pending'`, grantID).Scan(&n); err != nil {
		return false, err
	}
	return n >= maxPendingGuestRequests-guestReqReserved, nil
}

// CreateGuestRequest records a printed-QR scan. state is the registration state
// the visitor chose for the plate ("" = the tenant's home state); it is carried
// on the row so the approval applies the plate exactly as it was requested. Same
// plate, different state does NOT dedup against a pending row: plate alone is
// the identity the visitor sees and re-scans, and the approval reads the state
// from the row it approves.
func (s *Store) CreateGuestRequest(ctx context.Context, grantID, permitID int64, owner, plate, state, nonce string) (id int64, effNonce string, created bool, err error) {
	// Dedup (same plate re-scan reuses the pending request), the pending cap, and
	// the insert are ONE guarded statement: a separate check-then-insert lets two
	// simultaneous scans both pass the check and double-insert/over-fill.
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO guest_request (grant_id, owner, permit_id, plate, state, nonce, status, requested_at)
		 SELECT ?1, ?2, ?3, ?4, ?8, ?5, 'pending', ?6
		 WHERE NOT EXISTS (SELECT 1 FROM guest_request WHERE grant_id = ?1 AND plate = ?4 AND status = 'pending')
		   AND (SELECT COUNT(*) FROM guest_request WHERE grant_id = ?1 AND status = 'pending') < ?7`,
		grantID, owner, permitID, plate, nonce, nowUTC(), maxPendingGuestRequests, state)
	if err != nil {
		return 0, "", false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		id, err = res.LastInsertId()
		return id, nonce, true, err
	}
	// The guarded insert declined: either this plate already has a pending
	// request (reuse it) or the grant is at its pending cap.
	var existingID int64
	var existingNonce string
	e := s.db.QueryRowContext(ctx,
		`SELECT id, nonce FROM guest_request WHERE grant_id = ? AND plate = ? AND status = 'pending' ORDER BY id DESC LIMIT 1`,
		grantID, plate).Scan(&existingID, &existingNonce)
	if e == nil {
		return existingID, existingNonce, false, nil
	}
	if e != sql.ErrNoRows {
		return 0, "", false, e
	}
	return 0, "", false, ErrGuestRequestLimit
}

// ExpireGuestRequests marks pending requests older than before as expired, so a
// stale "approve this plate?" can't be actioned days later (approving an old row
// would silently put an unknown plate on today's permit) and abandoned scans
// drain out of the holder's queue. Expired rows read as denied to the visitor.
func (s *Store) ExpireGuestRequests(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE guest_request SET status = 'expired', decided_at = ? WHERE status = 'pending' AND requested_at < ?`,
		nowUTC(), before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// settledNonceGrace is how long a denied or expired request keeps its poll secret
// after being decided.
//
// It exists so the visitor can still LEARN the outcome. A denied or expired
// request has no until_ts (no approved run ever started), so a plain "past its
// window" test cleared the nonce on the very next sweep — sometimes in the same
// pass that expired it — and GuestRequestForPoll requires the nonce. The visitor's
// re-scan then resolved to nothing, so the distinct "your request timed out"
// message was unreachable and every unsuccessful outcome looked like a refusal.
// Matched to the 48h re-scan cookie window in the server package: once that cookie
// is gone nobody can present the nonce anyway, so holding it longer buys nothing.
const settledNonceGrace = 48 * time.Hour

// ClearSettledRequestNonces drops the poll secret from printed-QR requests once it
// can no longer tell a visitor anything, so a live capability does not sit in the
// table for the rest of its retention. An approved request keeps its nonce until
// its window ends; a denied or expired one keeps it for settledNonceGrace after
// the decision. Pending requests always keep theirs — the visitor is still polling.
func (s *Store) ClearSettledRequestNonces(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE guest_request SET nonce = ''
WHERE nonce != '' AND status != 'pending'
  AND (
        (until_ts != '' AND until_ts < ?)
     OR (until_ts = '' AND decided_at != '' AND decided_at < ?)
     OR (until_ts = '' AND decided_at = '')
      )`,
		now.UTC().Format(time.RFC3339),
		now.Add(-settledNonceGrace).UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PurgeDecidedGuestRequests deletes non-pending requests older than before.
// Visitor plates are PII; once a request is decided (or expired) there is no
// reason to keep it beyond a short audit window.
func (s *Store) PurgeDecidedGuestRequests(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM guest_request WHERE status != 'pending' AND requested_at < ?`,
		before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GuestRequestForPoll returns a request only if the nonce matches — the visitor's
// status check, safe against request-id enumeration.
func (s *Store) GuestRequestForPoll(ctx context.Context, id int64, nonce string) (GuestRequest, error) {
	return s.scanGuestRequest(s.db.QueryRowContext(ctx,
		`SELECT id, grant_id, owner, permit_id, plate, state, status, requested_at, decided_at, decided_by, until_at, until_ts
		 FROM guest_request WHERE id = ? AND nonce = ? AND nonce != ''`, id, nonce))
}

// rowScanner lets scanGuestRequest work over both QueryRow and Query results.
type rowScanner interface{ Scan(dest ...any) error }

func (s *Store) scanGuestRequest(row rowScanner) (GuestRequest, error) {
	var r GuestRequest
	var requested, decided, untilTS string
	err := row.Scan(&r.ID, &r.GrantID, &r.Owner, &r.PermitID, &r.Plate, &r.State, &r.Status, &requested, &decided, &r.DecidedBy, &r.Until, &untilTS)
	if err == sql.ErrNoRows {
		return GuestRequest{}, ErrNotFound
	}
	if err != nil {
		return GuestRequest{}, err
	}
	r.RequestedAt, _ = time.Parse(time.RFC3339, requested)
	r.DecidedAt, _ = time.Parse(time.RFC3339, decided)
	r.UntilTS, _ = time.Parse(time.RFC3339, untilTS)
	return r, nil
}

// GuestRequestByID returns a request (used by the visitor's polling status page).
func (s *Store) GuestRequestByID(ctx context.Context, id int64) (GuestRequest, error) {
	return s.scanGuestRequest(s.db.QueryRowContext(ctx,
		`SELECT id, grant_id, owner, permit_id, plate, state, status, requested_at, decided_at, decided_by, until_at, until_ts
		 FROM guest_request WHERE id = ?`, id))
}

// ListPendingRequests returns an owner's still-pending printed-QR requests, newest
// first (the approvals queue).
func (s *Store) ListPendingRequests(ctx context.Context, owner string) ([]GuestRequest, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, grant_id, owner, permit_id, plate, state, status, requested_at, until_at FROM guest_request
		 WHERE owner = ? AND status = 'pending' ORDER BY id DESC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GuestRequest
	for rows.Next() {
		var r GuestRequest
		var requested string
		if err := rows.Scan(&r.ID, &r.GrantID, &r.Owner, &r.PermitID, &r.Plate, &r.State, &r.Status, &requested, &r.Until); err != nil {
			return nil, err
		}
		r.RequestedAt, _ = time.Parse(time.RFC3339, requested)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListRecentDecidedRequests returns an owner's decided (approved/denied/expired)
// printed-QR requests since the given time, newest decision first. It feeds the
// guests page's recent-activity list, so every account member — not just the one
// who decided — can see how a request was resolved.
func (s *Store) ListRecentDecidedRequests(ctx context.Context, owner string, since time.Time) ([]GuestRequest, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, grant_id, owner, permit_id, plate, state, status, requested_at, decided_at, decided_by, until_at, until_ts
		 FROM guest_request
		 WHERE owner = ? AND status != 'pending' AND decided_at >= ?
		 ORDER BY decided_at DESC, id DESC`,
		owner, since.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GuestRequest
	for rows.Next() {
		r, err := s.scanGuestRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DecideGuestRequest approves or denies a pending request, scoped to owner. It
// records who decided and (on approval) when the granted window ends, so the
// decision stays legible later — to the visitor re-scanning the door code and
// to the other account members. It returns the request (so the caller can
// apply the plate on approval) or ErrNotFound if it is not the owner's or no
// longer pending.
func (s *Store) DecideGuestRequest(ctx context.Context, owner string, id int64, approve bool, until string, decidedBy string, untilTS time.Time) (GuestRequest, error) {
	status := "denied"
	if approve {
		status = "approved"
	}
	untilStamp := ""
	if !untilTS.IsZero() {
		untilStamp = untilTS.UTC().Format(time.RFC3339)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE guest_request SET status = ?, decided_at = ?, decided_by = ?, until_at = ?, until_ts = ?
		 WHERE id = ? AND owner = ? AND status = 'pending'`,
		status, nowUTC(), decidedBy, until, untilStamp, id, owner)
	if err != nil {
		return GuestRequest{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return GuestRequest{}, ErrNotFound
	}
	return s.GuestRequestByID(ctx, id)
}
