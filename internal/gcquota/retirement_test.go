// SPDX-License-Identifier: AGPL-3.0-only

package gcquota

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/myne-md/myne-server/internal/ids"
)

// The retirement reclaimer (myne-md/myne-server#17). The registry test covers the grace
// window; this covers the ORDER, which is the part that decides whether a failed reclaim is
// retried or lost forever.

type reclaimFixture struct {
	due       map[ids.AccountNumberHash][]ids.BlobID
	reclaimed []ids.BlobID
	acked     []ids.BlobID
	calls     int
	fail      map[ids.BlobID]error
	absent    error
	metrics   int
}

var errDisk = errors.New("disk on fire")

func (f *reclaimFixture) reclaimer() *RetirementReclaimer {
	return NewRetirementReclaimer(
		func() map[ids.AccountNumberHash][]ids.BlobID { return f.due },
		func(_ ids.AccountNumberHash, id ids.BlobID) error {
			f.calls++
			if err, ok := f.fail[id]; ok {
				return err
			}
			f.reclaimed = append(f.reclaimed, id)
			return nil
		},
		func(_ ids.AccountNumberHash, id ids.BlobID) { f.acked = append(f.acked, id) },
		func(err error) bool { return f.absent != nil && errors.Is(err, f.absent) },
		func(n int) { f.metrics += n },
		time.Hour,
	)
}

func acctID(b byte) ids.AccountNumberHash {
	var a ids.AccountNumberHash
	for i := range a {
		a[i] = b
	}
	return a
}

func blobID(b byte) ids.BlobID {
	var id ids.BlobID
	for i := range id {
		id[i] = b
	}
	return id
}

func TestReclaimer_AcksWhatItReclaimed(t *testing.T) {
	a := acctID(1)
	f := &reclaimFixture{due: map[ids.AccountNumberHash][]ids.BlobID{a: {blobID(1), blobID(2)}}}
	reclaimed, absent := f.reclaimer().RunOnce()
	if reclaimed != 2 || absent != 0 {
		t.Fatalf("RunOnce = (%d reclaimed, %d absent), want (2, 0)", reclaimed, absent)
	}
	if len(f.acked) != 2 {
		t.Fatalf("acked %d ids, want 2 (an unacked reclaim is re-reported forever)", len(f.acked))
	}
	if f.metrics != 2 {
		t.Fatalf("onReclaim fired %d times, want 2", f.metrics)
	}
}

func TestReclaimer_LeavesAFailedReclaimDue(t *testing.T) {
	a := acctID(1)
	f := &reclaimFixture{
		due:  map[ids.AccountNumberHash][]ids.BlobID{a: {blobID(1)}},
		fail: map[ids.BlobID]error{blobID(1): errDisk},
	}
	reclaimed, absent := f.reclaimer().RunOnce()
	if reclaimed != 0 || absent != 0 {
		t.Fatalf("a failed reclaim must count as neither: (%d, %d)", reclaimed, absent)
	}
	if len(f.acked) != 0 {
		t.Fatal("a failed reclaim must NOT be acked: that is the permanent leak this order exists to prevent")
	}
	if f.metrics != 0 {
		t.Fatal("a failed reclaim must not report progress to the metrics")
	}
}

func TestReclaimer_AcksAnAbsentBlobWithoutCountingItAsReclaimed(t *testing.T) {
	a := acctID(1)
	f := &reclaimFixture{
		due:    map[ids.AccountNumberHash][]ids.BlobID{a: {blobID(1)}},
		absent: ErrRetiredBlobAbsent,
		fail:   map[ids.BlobID]error{blobID(1): ErrRetiredBlobAbsent},
	}
	reclaimed, absent := f.reclaimer().RunOnce()
	if reclaimed != 0 || absent != 1 {
		t.Fatalf("RunOnce = (%d, %d), want (0, 1): nothing was freed", reclaimed, absent)
	}
	if len(f.acked) != 1 {
		t.Fatal("an absent blob has nothing to free, so it must be acked rather than retried forever")
	}
	if f.metrics != 0 {
		t.Fatal("an absent blob is not a reclamation and must not move that counter")
	}
}

// ErrRetiredBlobAbsent is the fixture's stand-in for the store's not-found error; the real
// wiring passes store.ErrNotFound, and the seam exists so this package does not import it.
var ErrRetiredBlobAbsent = errors.New("fixture: no such blob")

func TestReclaimer_StopsOnContextCancel(t *testing.T) {
	a := acctID(1)
	f := &reclaimFixture{due: map[ids.AccountNumberHash][]ids.BlobID{a: {blobID(1)}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.reclaimer().Start(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after its context was cancelled")
	}
}
