package parking

import (
	"log"
	"time"
)

// Per-owner backoff. When the portal pushes one account back (429/403/503), that
// account is put in a cooldown that grows with consecutive strikes, so the
// scheduler stops re-hitting a portal that is already refusing it — a soft block
// escalates to a hard one exactly by being hammered. The fleet breaker (breaker.go)
// is the counterpart for the case where MANY owners are pushed back at once.

func (c *Client) cooldownFor(owner string) (time.Duration, bool) {
	if v, ok := c.cooldownUntil.Load(owner); ok {
		if d := time.Until(v.(time.Time)); d > 0 {
			return d, true
		}
	}
	return 0, false
}

func (c *Client) penalize(owner string, retryAfter time.Duration) {
	c.strikeMu.Lock()
	n, _ := c.strikes.LoadOrStore(owner, 0)
	strikes := n.(int) + 1
	c.strikes.Store(owner, strikes)
	c.strikeMu.Unlock()

	backoff := retryAfter
	if backoff <= 0 {
		backoff = time.Duration(1<<min(strikes, 6)) * time.Minute // up to 64m
	}
	if backoff > 2*time.Hour {
		backoff = 2 * time.Hour
	}
	c.cooldownUntil.Store(owner, time.Now().Add(backoff))
	c.traffic.pushback.Add(1)
	if c.breaker.onPushback(time.Now(), owner, retryAfter) {
		_, wait := c.breaker.state(time.Now())
		log.Printf("parking: FLEET CIRCUIT OPEN — multiple owners pushed back at once (likely an edge/IP block); pausing ALL council traffic for %s", wait.Round(time.Second))
	}
	c.persistBreaker()
}

func (c *Client) clearPenalty(owner string) {
	c.strikes.Delete(owner)
	c.cooldownUntil.Delete(owner)
}

func (c *Client) noteCouncilSuccess(owner string, permit breakerPermit) {
	if c.breaker.onSuccess(time.Now(), owner, permit) {
		log.Printf("parking: fleet circuit closed — the council edge is serving us again; council traffic resumed")
		c.persistBreaker() // clear the persisted pause so a restart doesn't re-pause
	}
}
