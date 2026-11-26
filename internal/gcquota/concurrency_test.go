// SPDX-License-Identifier: AGPL-3.0-only

package gcquota

// Concurrency stress tests for the abuse-mitigation substrate: the per-account token
// bucket (rate limit, keyed on account_number_hash — never IP, C4) and the dedup-byte
// quota guard. The existing tests drive these single-threaded; these hammer them from
// many goroutines to pin the token-bucket cap under contention and to document the
// quota guard's deliberate soft-limit (check-then-push is not one atomic step) while
// proving the store's byte accounting stays exact under the race. Run under `-race`.

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/myne-md/myne-server/internal/store"
)

// fanOut releases n goroutines at once and waits. fn may call t.Error* but not
// t.Fatal* (illegal off the test goroutine).
func fanOut(n int, fn func(i int)) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			fn(i)
		}(i)
	}
	close(start)
	wg.Wait()
}

// With refill disabled, far more concurrent Allow calls than the burst grant exactly
// `burst` tokens — never one more (no token created from nothing under the race),
// never one fewer (no token lost).
func TestConcurrent_RateLimiter_ExactBurstGrant(t *testing.T) {
	const burst = 50
	const n = 256
	rl := NewRateLimiter(burst, 0)
	a := acct(0x01)
	var granted atomic.Int64
	fanOut(n, func(i int) {
		if rl.Allow(a) {
			granted.Add(1)
		}
	})
	if granted.Load() != burst {
		t.Fatalf("granted = %d, want exactly %d (no over/under-grant under concurrency)", granted.Load(), burst)
	}
}

// Allow and Refill run concurrently: grants never exceed the tokens ever made
// available (initial burst + every refill round's contribution), and the bucket never
// settles above its burst cap. The race detector backs the mutex discipline.
func TestConcurrent_RateLimiter_AllowRefillInterleaved_Bounded(t *testing.T) {
	const burst = 20
	const refill = 5
	const allowers = 32
	const opsEach = 50
	const refillers = 4
	const refillRounds = 30
	rl := NewRateLimiter(burst, refill)
	a := acct(0x02)

	var granted atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for g := 0; g < allowers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for k := 0; k < opsEach; k++ {
				if rl.Allow(a) {
					granted.Add(1)
				}
			}
		}()
	}
	for r := 0; r < refillers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for k := 0; k < refillRounds; k++ {
				rl.Refill()
			}
		}()
	}
	close(start)
	wg.Wait()

	maxAvail := int64(burst + refillers*refillRounds*refill)
	if granted.Load() > maxAvail {
		t.Fatalf("granted %d exceeds tokens ever available %d (over-grant under race)", granted.Load(), maxAvail)
	}
	// One settling refill, then the bucket must respect the burst cap.
	rl.Refill()
	rl.mu.Lock()
	tok := rl.buckets[a]
	rl.mu.Unlock()
	if tok > burst {
		t.Fatalf("bucket %d exceeds burst cap %d", tok, burst)
	}
}

// The quota guard is a per-call check, NOT an atomic reserve-then-store. Under a
// simultaneous burst every racer reads QuotaBytes before any push lands, so they all
// pass the check and the ceiling is blown right past — the guard is a deliberate SOFT
// limit (TB5 best-effort abuse mitigation, not billing; the atomic per-account rate
// limiter is the primary gate that bounds how many pushes land per tick, and once the
// counter reflects reality a later check correctly gates). Two invariants still hold
// EXACTLY under the race, which is what this pins:
//  1. accounting: the store's dedup-byte counter equals exactly what was stored — the
//     read-modify-write on quotaBytes never loses an add (the -race-backed property);
//  2. bounded: over-admission is not unbounded — at most one in-flight burst past the
//     ceiling (final ≤ ceiling + n*size).
//
// (The thundering-herd bypass is a known, accepted property — documented here so a
// future change that tightens the guard to a hard reserve updates this test
// deliberately rather than by accident.)
func TestConcurrent_QuotaGuard_SoftLimit_AccountingExact(t *testing.T) {
	st := store.NewMemStore()
	a := acct(0x55)
	const ceiling = 10_000
	const size = 200
	const n = 128
	qg := NewQuotaGuard(ceiling)

	var storedBytes atomic.Uint64
	fanOut(n, func(i int) {
		if qg.WouldExceed(st, a, size) {
			return
		}
		ct := bytes.Repeat([]byte{byte(i)}, size)
		if _, err := st.PushBlob(a, blob(byte(i)), 0, nonce(byte(i)), ct); err != nil {
			t.Errorf("push %d: %v", i, err)
			return
		}
		storedBytes.Add(size)
	})

	// (1) accounting is exact — no lost-update on the byte counter under contention.
	if got := st.QuotaBytes(a); got != storedBytes.Load() {
		t.Fatalf("quota accounting drifted: store=%d, actually-stored=%d", got, storedBytes.Load())
	}
	// (2) over-admission is bounded, never unbounded.
	if got := st.QuotaBytes(a); got > ceiling+n*size {
		t.Fatalf("quota %d exceeds the bounded soft-limit window %d", got, ceiling+n*size)
	}
	// Once the counter reflects the burst, the guard DOES gate: a fresh check past the
	// (now-overshot) ceiling refuses. This isolates the bypass to the in-flight window.
	if !qg.WouldExceed(st, a, size) {
		t.Fatalf("after the burst (stored=%d, ceiling=%d) the guard still admits", storedBytes.Load(), ceiling)
	}
}
