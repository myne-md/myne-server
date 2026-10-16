// SPDX-License-Identifier: AGPL-3.0

package store

import (
	"errors"
	"os"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

// ReclaimRetired is the operation the retirement grace had no way to perform
// (myne-md/myne-server#17): drop a RETIRED namespace's ciphertext body without a tombstone
// record. Everything below is asserted against BOTH backends, because they are two
// implementations of one promise and a divergence between them is the kind of gap this whole
// family of bugs lives in.

func backends(t *testing.T) map[string]BlobStore {
	t.Helper()
	return map[string]BlobStore{
		"mem": NewMemStore(),
		"fs":  newTempFSStore(t),
	}
}

func newTempFSStore(t *testing.T) BlobStore {
	t.Helper()
	s, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	return s
}

func put(t *testing.T, s BlobStore, acct ids.AccountNumberHash, id ids.BlobID, body string) {
	t.Helper()
	if _, err := s.PutBlob(acct, id, []byte(body)); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
}

func TestReclaimRetired_ReleasesTheBodyAndKeepsTheRecord(t *testing.T) {
	for name, s := range backends(t) {
		t.Run(name, func(t *testing.T) {
			acct, id := testAccount(1), testBlob(2)
			put(t, s, acct, id, "ciphertext-of-a-retired-namespace")
			before := s.QuotaBytes(acct)
			if before == 0 {
				t.Fatal("the fixture stored nothing, so the quota assertion below would be vacuous")
			}

			if err := s.ReclaimRetired(acct, id); err != nil {
				t.Fatalf("ReclaimRetired: %v", err)
			}

			// The body is gone and the record is not: a reader sees "reclaimed", never a live
			// empty ciphertext (which would read as a real note whose content vanished).
			if _, _, err := s.GetBlob(acct, id); !errors.Is(err, ErrReclaimed) {
				t.Fatalf("GetBlob after reclaim = %v, want ErrReclaimed", err)
			}
			if got := s.QuotaBytes(acct); got != 0 {
				t.Fatalf("quota after reclaim = %d, want 0 (the bytes are gone; the accounting must say so)", got)
			}
			// Absent from the manifest, and the cursor advances ACROSS it rather than stalling
			// below the reclaim floor, which is what makes a reader full-reconcile (§11.2).
			metas, cursor := s.ChangedSince(acct, 0, 100)
			for _, m := range metas {
				if m.BlobID == id {
					t.Fatal("a reclaimed blob must be absent from ChangedSince")
				}
			}
			if cursor == 0 {
				t.Fatal("the cursor must advance across a reclaimed record, not stall at 0")
			}
			// A pull from a cursor that predates the reclaim is told to full-reconcile.
			if s.GCFloor(acct) == 0 {
				t.Fatal("the reclaim floor must cover the reclaimed record")
			}
		})
	}
}

func TestReclaimRetired_IsIdempotent(t *testing.T) {
	for name, s := range backends(t) {
		t.Run(name, func(t *testing.T) {
			acct, id := testAccount(1), testBlob(2)
			put(t, s, acct, id, "body")
			if err := s.ReclaimRetired(acct, id); err != nil {
				t.Fatalf("first reclaim: %v", err)
			}
			if err := s.ReclaimRetired(acct, id); err != nil {
				t.Fatalf("second reclaim must be a no-op, got %v", err)
			}
			if got := s.QuotaBytes(acct); got != 0 {
				t.Fatalf("quota after two reclaims = %d, want 0 (double-subtraction)", got)
			}
		})
	}
}

// A namespace can be retired before any blob arrives in it. That is not a failure — there is
// nothing to free — and the caller must be able to tell that apart from a disk error.
func TestReclaimRetired_AbsentBlobIsNotFound(t *testing.T) {
	for name, s := range backends(t) {
		t.Run(name, func(t *testing.T) {
			if err := s.ReclaimRetired(testAccount(1), testBlob(9)); !errors.Is(err, ErrNotFound) {
				t.Fatalf("reclaim of an absent blob = %v, want ErrNotFound", err)
			}
		})
	}
}

// A tombstoned blob that is ALSO retired keeps both records coherent: the retire path marks
// the tombstone reclaimed too, so the horizon-GC does not redo the work and the floor reflects
// the tombstone's own change-sequence.
func TestReclaimRetired_OverATombstoneKeepsBothRecords(t *testing.T) {
	for name, s := range backends(t) {
		t.Run(name, func(t *testing.T) {
			acct, id := testAccount(1), testBlob(2)
			put(t, s, acct, id, "body")
			if err := s.SetTombstone(acct, id, 1); err != nil {
				t.Fatalf("SetTombstone: %v", err)
			}
			if err := s.ReclaimRetired(acct, id); err != nil {
				t.Fatalf("ReclaimRetired: %v", err)
			}
			_, _, reclaimed, ok := s.TombstoneRecord(acct, id)
			if !ok || !reclaimed {
				t.Fatalf("tombstone record after a retired reclaim: ok=%v reclaimed=%v", ok, reclaimed)
			}
			// Reclaiming an already-reclaimed tombstone is a no-op, not a second subtraction.
			if err := s.ReclaimTombstone(acct, id); err != nil {
				t.Fatalf("ReclaimTombstone after ReclaimRetired: %v", err)
			}
			if got := s.QuotaBytes(acct); got != 0 {
				t.Fatalf("quota = %d, want 0", got)
			}
		})
	}
}

// The FS backend must leave no ciphertext on disk. This is the half a quota counter cannot
// show, and the half the whole operation is for.
func TestReclaimRetired_FSRemovesTheFile(t *testing.T) {
	s, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	acct, id := testAccount(1), testBlob(2)
	put(t, s, acct, id, "body")
	path := s.blobPath(acct, id)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the fixture's blob file is missing before the reclaim: %v", err)
	}
	if err := s.ReclaimRetired(acct, id); err != nil {
		t.Fatalf("ReclaimRetired: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the ciphertext file still exists after the reclaim (err=%v)", err)
	}
}
