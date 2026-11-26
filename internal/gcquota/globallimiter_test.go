// SPDX-License-Identifier: AGPL-3.0-only

package gcquota

import (
	"sync"
	"testing"
)

// A drained bucket grants exactly `burst` before refusing.
func TestGlobalLimiter_ExactBurstGrant(t *testing.T) {
	g := NewGlobalLimiter(5, 0)
	granted := 0
	for i := 0; i < 20; i++ {
		if g.Allow() {
			granted++
		}
	}
	if granted != 5 {
		t.Fatalf("granted %d, want 5 (burst)", granted)
	}
}

// Refill never lifts the bucket above burst.
func TestGlobalLimiter_RefillCap(t *testing.T) {
	g := NewGlobalLimiter(3, 10)
	for i := 0; i < 3; i++ {
		g.Allow() // drain
	}
	if g.Allow() {
		t.Fatal("bucket should be empty after draining burst")
	}
	g.Refill() // +10, capped at burst=3
	granted := 0
	for i := 0; i < 10; i++ {
		if g.Allow() {
			granted++
		}
	}
	if granted != 3 {
		t.Fatalf("post-refill granted %d, want 3 (capped at burst)", granted)
	}
}

// Under concurrent contention the bucket grants exactly burst — no double-spend
// (run with -race to exercise the mutex).
func TestGlobalLimiter_ConcurrentExactBurst(t *testing.T) {
	g := NewGlobalLimiter(100, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.Allow() {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if granted != 100 {
		t.Fatalf("concurrent granted %d, want exactly 100", granted)
	}
}
