// SPDX-License-Identifier: AGPL-3.0-or-later

package gcquota

import (
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// TestScheduler_RunOnceSweepsAllAccountsAndReportsReclaim verifies the scheduler
// drives the existing substrate across every account and reports the aggregate
// reclaimed count via onReclaim (the metrics hook) — without re-implementing GC.
func TestScheduler_RunOnceSweepsAllAccountsAndReportsReclaim(t *testing.T) {
	s := store.NewMemStore()
	reg := auth.NewRegistry()

	var a ids.AccountNumberHash
	a[0] = 0xAB
	var bid ids.BlobID
	bid[0] = 0x01

	// One blob, tombstoned, with NO active devices → every (zero) active device has
	// trivially acked → the horizon-GC reclaims it.
	if _, err := s.PutBlob(a, bid, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTombstone(a, bid, 1); err != nil {
		t.Fatal(err)
	}

	gc := NewHorizonGC(s, reg, Policy{HorizonMarkers: 30})
	reclaimedReported := 0
	sched := NewScheduler(gc, s.ListAccounts, func(n int) { reclaimedReported += n }, 0)
	sched.marker = func() uint64 { return 100 } // injected coarse marker (no real clock)

	reclaimed, _ := sched.RunOnce()
	if reclaimed != 1 {
		t.Fatalf("RunOnce reclaimed = %d, want 1", reclaimed)
	}
	if reclaimedReported != 1 {
		t.Fatalf("onReclaim hook reported = %d, want 1", reclaimedReported)
	}
	// The body is reclaimed in the underlying store (substrate did the work).
	if _, _, rec, ok := s.TombstoneRecord(a, bid); !ok || !rec {
		t.Fatalf("tombstone not reclaimed by the scheduler-driven sweep")
	}
}

func TestScheduler_NoAccountsIsNoop(t *testing.T) {
	s := store.NewMemStore()
	gc := NewHorizonGC(s, auth.NewRegistry(), Policy{HorizonMarkers: 30})
	sched := NewScheduler(gc, s.ListAccounts, nil, 0)
	sched.marker = func() uint64 { return 1 }
	if r, rt := sched.RunOnce(); r != 0 || rt != 0 {
		t.Fatalf("empty sweep = (%d,%d), want (0,0)", r, rt)
	}
}
