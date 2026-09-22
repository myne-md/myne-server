// SPDX-License-Identifier: AGPL-3.0

package store

import (
	"testing"
	"time"

	"github.com/myne-md/myne-server/internal/ids"
)

func testAccount(b byte) ids.AccountNumberHash {
	var a ids.AccountNumberHash
	a[0] = b
	return a
}

func testBlob(b byte) ids.BlobID {
	var id ids.BlobID
	id[0] = b
	return id
}

// The grace window is the whole point of the registry: a retired namespace is
// refused immediately, but its bytes survive until the window elapses, so an
// in-flight rotation can finish. A reclaim that fired at record time would lose
// the recovery window; one that never fired would retain forever.
func TestRetirements_ReclaimOnlyAfterGrace(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	r := NewRetirements(time.Hour).WithClock(func() time.Time { return now })
	acct := testAccount(1)
	id := testBlob(2)

	r.Record(acct, 1, 2, []ids.BlobID{id})

	if !r.IsRetired(acct, id) {
		t.Fatal("a recorded sync id must be retired immediately")
	}
	if epoch, ok := r.HighestRetiredEpoch(acct); !ok || epoch != 1 {
		t.Fatalf("highest retired epoch = %d ok=%v, want 1", epoch, ok)
	}
	if r.IsRetired(acct, testBlob(3)) {
		t.Fatal("an unrecorded sync id must not be retired")
	}

	if due := r.DueReclaims(); len(due) != 0 {
		t.Fatalf("reclaim due before the grace: %v", due)
	}
	now = now.Add(59 * time.Minute)
	if due := r.DueReclaims(); len(due) != 0 {
		t.Fatalf("reclaim due 59 minutes into a 1 hour grace: %v", due)
	}
	now = now.Add(2 * time.Minute)
	due := r.DueReclaims()
	if len(due[acct]) != 1 || due[acct][0] != id {
		t.Fatalf("reclaim after the grace = %v, want [%v]", due, id)
	}
	// Reported exactly once: a second sweep does not reclaim a missing blob.
	if due := r.DueReclaims(); len(due) != 0 {
		t.Fatalf("reclaim reported twice: %v", due)
	}
	// The id stays retired even after its blob is gone, so a stale push cannot
	// resurrect the namespace.
	if !r.IsRetired(acct, id) {
		t.Fatal("a reclaimed id must stay retired")
	}
}

// A retirement for one vault must not refuse writes in another.
func TestRetirements_AreVaultScoped(t *testing.T) {
	r := NewRetirements(time.Hour)
	a, b := testAccount(1), testAccount(2)
	id := testBlob(9)
	r.Record(a, 1, 2, []ids.BlobID{id})
	if !r.IsRetired(a, id) {
		t.Fatal("retired for its own vault")
	}
	if r.IsRetired(b, id) {
		t.Fatal("a retirement must not leak into another vault")
	}
}

// A lower epoch arriving late must not walk the recorded floor backwards.
func TestRetirements_DoNotLowerTheEpoch(t *testing.T) {
	r := NewRetirements(time.Hour)
	acct := testAccount(1)
	r.Record(acct, 5, 6, nil)
	r.Record(acct, 2, 3, nil)
	if epoch, _ := r.HighestRetiredEpoch(acct); epoch != 5 {
		t.Fatalf("highest retired epoch = %d, want 5", epoch)
	}
}
