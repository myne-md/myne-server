// SPDX-License-Identifier: AGPL-3.0

package store

// Batch coalescing (myne-server#6). FSStore.persist rebuilds and rewrites the WHOLE
// vault index, so a mutation loop that persisted per mutation cost O(N²) — a push
// carrying 50k blobs marshalled ~1.25e9 blob-meta entries and issued ~200k fsyncs
// against a 71 MB payload, and never returned. These tests pin the property that
// makes it linear again: N mutations inside one Batch produce exactly ONE physical
// index write, and that write still happens on the failure paths, so the in-memory
// index never runs ahead of disk.
//
// Physical writes are counted by swapping FSStore.writeIndex — the same injectable
// -write-primitive trick accounts.Store uses to assert its own coalescing.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

// blobN builds the n-th distinct blob id. The byte-keyed blob() helper only spans
// 256 ids and these tests need hundreds at once.
func blobN(n int) ids.BlobID {
	var id ids.BlobID
	binary.BigEndian.PutUint64(id[:8], uint64(n))
	return id
}

// countingFS returns a store whose index writes are counted (and still performed,
// so the on-disk result stays assertable).
func countingFS(t *testing.T) (*FSStore, string, *atomic.Int64) {
	t.Helper()
	s, dir := newFS(t)
	var writes atomic.Int64
	inner := s.writeIndex
	s.writeIndex = func(path string, data []byte) error {
		writes.Add(1)
		return inner(path, data)
	}
	return s, dir, &writes
}

// pushN pushes n distinct new blobs into one vault.
func pushN(t *testing.T, s *FSStore, a ids.AccountNumberHash, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := s.PushBlob(a, blobN(i), 0, nonce(byte(i)), []byte("ct")); err != nil {
			t.Fatalf("PushBlob %d: %v", i, err)
		}
	}
}

// The regression gate for #6: the same N mutations cost N index writes loose and
// exactly ONE inside a batch — and the single write carries all N blobs, so the
// saving is not a lost update.
func TestFSStore_BatchCoalescesIndexWrites(t *testing.T) {
	// n is kept modest because the assertion is exact (n vs 1) — the unbatched half
	// pays 2 fsyncs per mutation, and that wall-clock IS the bug being measured.
	const n = 200
	a := acct(0x01)

	loose, _, looseWrites := countingFS(t)
	pushN(t, loose, a, n)
	if got := looseWrites.Load(); got != int64(n) {
		t.Fatalf("unbatched: index writes = %d, want %d (one per mutation)", got, n)
	}

	batched, dir, batchedWrites := countingFS(t)
	if err := batched.Batch(a, func() error {
		pushN(t, batched, a, n)
		return nil
	}); err != nil {
		t.Fatalf("Batch: %v", err)
	}
	if got := batchedWrites.Load(); got != 1 {
		t.Fatalf("batched: index writes = %d, want 1 for the whole batch", got)
	}

	// The coalesced write is the complete one: reopen from disk and find every blob.
	reopened, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	for i := 0; i < n; i++ {
		v, err := reopened.BlobVersion(a, blobN(i))
		if err != nil || v != 1 {
			t.Fatalf("blob %d after reopen: v=%d err=%v", i, v, err)
		}
	}
}

// A batch is a durability scope, not a transaction: when fn fails partway the
// mutations it already applied stay applied, so the index MUST still be written.
// Skipping it would leave the in-memory index ahead of disk — a reopen would then
// serve stale versions and hand every later push a CAS it cannot win.
func TestFSStore_BatchWritesIndexWhenFnFails(t *testing.T) {
	a := acct(0x02)
	boom := errors.New("boom")

	s, dir, writes := countingFS(t)
	err := s.Batch(a, func() error {
		pushN(t, s, a, 3)
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Batch swallowed fn's error: %v", err)
	}
	if got := writes.Load(); got != 1 {
		t.Fatalf("index writes = %d, want 1 even though fn failed", got)
	}

	reopened, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := reopened.BlobVersion(a, blobN(i)); err != nil {
			t.Fatalf("blob %d applied before the failure is missing from disk: %v", i, err)
		}
	}
}

// Nested batches over one vault write once, when the OUTERMOST one ends.
func TestFSStore_BatchNestedWritesOnceAtTheOutermostEnd(t *testing.T) {
	a := acct(0x03)
	s, _, writes := countingFS(t)

	if err := s.Batch(a, func() error {
		pushN(t, s, a, 2)
		if err := s.Batch(a, func() error {
			pushN(t, s, a, 2)
			return nil
		}); err != nil {
			return err
		}
		if got := writes.Load(); got != 0 {
			t.Errorf("inner batch wrote the index (%d writes) — the outermost one owns the write", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("Batch: %v", err)
	}
	if got := writes.Load(); got != 1 {
		t.Fatalf("index writes = %d, want 1 across the nested batches", got)
	}
}

// A batch's coalesced write must not resurrect an account deleted inside it. The
// mutations before the delete marked the vault dirty; without the deleted check the
// write at the end of the batch would recreate index.json under a removed account.
func TestFSStore_BatchOverDeletedAccountWritesNothingBack(t *testing.T) {
	a := acct(0x04)
	s, dir, _ := countingFS(t)

	if err := s.Batch(a, func() error {
		pushN(t, s, a, 3)
		return s.DeleteAccount(a)
	}); err != nil {
		t.Fatalf("Batch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, hex.EncodeToString(a[:]))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted account dir survived the batch's coalesced write: %v", err)
	}
}

// MemStore keeps no on-disk bookkeeping, so its Batch is a pass-through — but it
// must still run fn exactly once and surface fn's error, because the push handler
// wraps its whole mutation section in it whichever backend it was handed.
func TestMemStore_BatchRunsFnOnceAndPropagatesItsError(t *testing.T) {
	s := NewMemStore()
	a := acct(0x05)

	calls := 0
	if err := s.Batch(a, func() error { calls++; return nil }); err != nil {
		t.Fatalf("Batch: %v", err)
	}
	if calls != 1 {
		t.Fatalf("fn ran %d times, want 1", calls)
	}

	boom := errors.New("boom")
	if err := s.Batch(a, func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("Batch swallowed fn's error: %v", err)
	}
}
