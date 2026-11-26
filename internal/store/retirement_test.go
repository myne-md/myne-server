// SPDX-License-Identifier: AGPL-3.0-only

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

	if due := r.DueRetirements(); len(due) != 0 {
		t.Fatalf("reclaim due before the grace: %v", due)
	}
	now = now.Add(59 * time.Minute)
	if due := r.DueRetirements(); len(due) != 0 {
		t.Fatalf("reclaim due 59 minutes into a 1 hour grace: %v", due)
	}
	now = now.Add(2 * time.Minute)
	due := r.DueRetirements()
	if len(due[acct]) != 1 || due[acct][0] != id {
		t.Fatalf("reclaim after the grace = %v, want [%v]", due, id)
	}
	// Reported until it is ACKED, not consumed on the way out: the caller's next step is a
	// storage write that can fail, and a peek that consumed would lose a failed reclaim
	// permanently (myne-md/myne-server#17).
	if again := r.DueRetirements(); len(again[acct]) != 1 {
		t.Fatalf("an unacked reclamation must stay due for a retry, got %v", again)
	}
	r.Reclaimed(acct, id)
	// Reported exactly once AFTER the ack: a second sweep does not reclaim a missing blob.
	if done := r.DueRetirements(); len(done) != 0 {
		t.Fatalf("reclaim reported again after being acked: %v", done)
	}
	// Acking twice is not an error: the reclaim it acknowledges is itself idempotent.
	r.Reclaimed(acct, id)
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
