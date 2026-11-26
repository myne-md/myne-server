// SPDX-License-Identifier: AGPL-3.0-only

package authpersist

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// A burst of triggers coalesces into far fewer physical writes; one Flush drains the
// dirty flag with exactly one write, and a second Flush (nothing dirty) writes nothing.
func TestCoordinator_CoalescesWrites(t *testing.T) {
	e := newEnv(t, t.TempDir())
	var writes atomic.Int64
	e.coord.write = func(string, []byte) error { writes.Add(1); return nil } // counting seam

	for i := 0; i < 100; i++ {
		e.coord.trigger()
	}
	if got := writes.Load(); got != 0 {
		t.Fatalf("writes after triggers-only = %d, want 0 (coalesced, still dirty)", got)
	}
	e.coord.Flush()
	if got := writes.Load(); got != 1 {
		t.Fatalf("writes after flush = %d, want exactly 1", got)
	}
	e.coord.Flush()
	if got := writes.Load(); got != 1 {
		t.Fatalf("writes after idempotent flush = %d, want still 1", got)
	}
}

// Start's ctx-cancel path performs a final flush so a pending write survives a
// graceful shutdown.
func TestCoordinator_StartFlushesOnShutdown(t *testing.T) {
	e := newEnv(t, t.TempDir())
	var writes atomic.Int64
	e.coord.write = func(string, []byte) error { writes.Add(1); return nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.coord.Start(ctx); close(done) }()

	e.coord.trigger()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
	if got := writes.Load(); got < 1 {
		t.Fatalf("shutdown flush wrote %d times, want >= 1 (pending state must persist)", got)
	}
}
