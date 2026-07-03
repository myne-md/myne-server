// SPDX-License-Identifier: AGPL-3.0

package gcquota

import "sync"

// GlobalLimiter is a single, account-INDEPENDENT token bucket for the pre-auth
// surface (device registration + the SCRAM handshake + the pre-auth vault.meta
// fetch). Those requests carry no authenticated session, so the per-account
// RateLimiter cannot key them — and keying on an attacker-controlled query value
// (e.g. account_number_hash) or on the source IP is forbidden (C4/AS14, and a
// query-keyed map is itself an unbounded-map DoS). A single scalar bucket is the
// honest answer: it holds NO per-key state, so it is STRUCTURALLY incapable of
// keying on IP/account (the same "no per-identity dimension" invariant as the
// aggregate metrics surface). It only smooths pre-auth churn; the hard memory/
// disk bounds are the caps in the handlers (account/handshake ceilings). Under a
// sustained flood pre-auth availability degrades to 429 — accepted, best-effort
// (threat-model DoS posture; no proof-of-work in v1, server-protocol §5.3).
//
// Refill is driven by an explicit Refill() tick (the live server's per-second
// ticker), so the policy carries no wall-clock and is deterministic to test —
// mirroring the per-account RateLimiter in this package.
type GlobalLimiter struct {
	mu     sync.Mutex
	burst  uint64
	refill uint64
	tokens uint64
}

// NewGlobalLimiter creates a limiter with the given burst (bucket capacity) and
// per-tick refill amount. The bucket starts full (burst).
func NewGlobalLimiter(burst, refillPerTick uint64) *GlobalLimiter {
	return &GlobalLimiter{burst: burst, refill: refillPerTick, tokens: burst}
}

// Allow consumes one token, returning false if the bucket is empty (the caller
// maps false → HTTP 429 "rate"). No account/IP argument — the limit is global by
// construction.
func (g *GlobalLimiter) Allow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.tokens == 0 {
		return false
	}
	g.tokens--
	return true
}

// Refill adds the per-tick refill to the bucket, capped at burst. The live server
// calls this on a ticker; tests call it directly.
func (g *GlobalLimiter) Refill() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tokens += g.refill
	if g.tokens > g.burst {
		g.tokens = g.burst
	}
}
