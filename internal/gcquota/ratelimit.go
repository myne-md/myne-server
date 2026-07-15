// SPDX-License-Identifier: AGPL-3.0

package gcquota

import (
	"sync"

	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// RateLimiter is a per-account token-bucket keyed on account_number_hash — NEVER
// IP (C4). Refill is driven by an explicit Refill() tick (a background ticker in
// the live server) so the policy logic carries no wall-clock and is deterministic
// to test. A per-device sub-limit can layer on top using the same mechanism.
type RateLimiter struct {
	mu      sync.Mutex
	burst   uint64
	refill  uint64
	buckets map[ids.AccountNumberHash]uint64
}

// NewRateLimiter creates a limiter with the given burst (bucket capacity) and
// per-tick refill amount.
func NewRateLimiter(burst, refillPerTick uint64) *RateLimiter {
	return &RateLimiter{burst: burst, refill: refillPerTick, buckets: make(map[ids.AccountNumberHash]uint64)}
}

// Allow consumes one token for the account, returning false if the bucket is empty
// (caller maps false → HTTP 429 "rate"). A first-seen account starts full (burst).
func (r *RateLimiter) Allow(account ids.AccountNumberHash) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	tokens, seen := r.buckets[account]
	if !seen {
		tokens = r.burst
	}
	if tokens == 0 {
		r.buckets[account] = 0
		return false
	}
	r.buckets[account] = tokens - 1
	return true
}

// Refill adds the per-tick refill to every active bucket, capped at burst. The live
// server calls this on a ticker; tests call it directly.
func (r *RateLimiter) Refill() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for acct, tokens := range r.buckets {
		tokens += r.refill
		if tokens > r.burst {
			tokens = r.burst
		}
		r.buckets[acct] = tokens
	}
}

// QuotaGuard enforces a per-account dedup-byte ceiling (AS17). A ceiling of 0 means
// unlimited (the hosted value is set by the payment epic, MYND-430; self-host sets
// its own).
type QuotaGuard struct {
	ceiling  uint64
	override func(account ids.AccountNumberHash, base uint64) uint64 // optional per-account effective ceiling (MYND-506)
}

// NewQuotaGuard creates a guard with the given ceiling (0 = unlimited).
func NewQuotaGuard(ceilingBytes uint64) *QuotaGuard {
	return &QuotaGuard{ceiling: ceilingBytes}
}

// WithOverride installs a per-account effective-ceiling resolver so an operator's
// per-account quota override wins over the global default (MYND-506). fn receives the
// account + the global ceiling and returns the ceiling to enforce (0 = unlimited).
func (q *QuotaGuard) WithOverride(fn func(account ids.AccountNumberHash, base uint64) uint64) *QuotaGuard {
	q.override = fn
	return q
}

// effective returns the ceiling to enforce for an account: the override when set,
// else the global ceiling.
func (q *QuotaGuard) effective(account ids.AccountNumberHash) uint64 {
	if q.override != nil {
		return q.override(account, q.ceiling)
	}
	return q.ceiling
}

// WouldExceedTotalForAccount reports whether currentBytes+addBytes would cross the
// account's effective ceiling (0 = unlimited). Store-agnostic so a caller holding a
// byte total drawn from more than one source can gate on the combined figure — this
// is how the attachment transport folds its bytes into the SAME per-account AS17
// ceiling as the blob store (unified total, no per-subsystem ceiling to bypass), and
// the per-account override applies uniformly across both paths.
func (q *QuotaGuard) WouldExceedTotalForAccount(account ids.AccountNumberHash, currentBytes, addBytes uint64) bool {
	c := q.effective(account)
	if c == 0 {
		return false
	}
	return currentBytes+addBytes > c
}

// WouldExceed reports whether storing addBytes more would push the account over its
// effective ceiling (caller maps true → HTTP 507 "quota"). Uses the dedup'd substrate
// counter from the blob store (the sync-push path).
func (q *QuotaGuard) WouldExceed(s store.BlobStore, account ids.AccountNumberHash, addBytes uint64) bool {
	return q.WouldExceedTotalForAccount(account, s.QuotaBytes(account), addBytes)
}
