// SPDX-License-Identifier: AGPL-3.0

package store

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func newFS(t *testing.T) (*FSStore, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	return s, dir
}

func TestFSStore_PutGetRoundTripAndVersion(t *testing.T) {
	s, _ := newFS(t)
	a, id := acct(0x01), blob(0xAA)
	v1, err := s.PutBlob(a, id, []byte("ct-1"))
	if err != nil || v1 != 1 {
		t.Fatalf("PutBlob v1: v=%d err=%v", v1, err)
	}
	v2, _ := s.PutBlob(a, id, []byte("ct-2"))
	if v2 != 2 {
		t.Fatalf("version not monotonic: %d", v2)
	}
	got, v, err := s.GetBlob(a, id)
	if err != nil || v != 2 || !bytes.Equal(got, []byte("ct-2")) {
		t.Fatalf("GetBlob: %q v=%d err=%v", got, v, err)
	}
}

func TestFSStore_IdempotentRePut(t *testing.T) {
	s, _ := newFS(t)
	a, id := acct(2), blob(2)
	v1, _ := s.PutBlob(a, id, []byte("same"))
	v2, _ := s.PutBlob(a, id, []byte("same"))
	if v1 != 1 || v2 != 1 {
		t.Fatalf("idempotent re-put bumped version: v1=%d v2=%d", v1, v2)
	}
}

func TestFSStore_VaultIsolationOnDisk(t *testing.T) {
	s, dir := newFS(t)
	a1, a2 := acct(0x01), acct(0x02)
	id := blob(0xAA)
	if _, err := s.PutBlob(a1, id, []byte("a1")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GetBlob(a2, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-vault read leaked: %v", err)
	}
	// On-disk layout: per-vault dir keyed on account_number_hash; blob under blobs/.
	want := filepath.Join(dir, hex.EncodeToString(a1[:]), "blobs", hex.EncodeToString(id[:]))
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("blob not at per-vault namespaced path %s: %v", want, err)
	}
	// No flat content-addressed bucket: the path is account-scoped, not a global hash.
	if _, err := os.Stat(filepath.Join(dir, "blobs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("found a global blobs/ bucket — must be per-vault namespaced")
	}
}

func TestFSStore_PushBlobCAS(t *testing.T) {
	s, _ := newFS(t)
	a, id := acct(3), blob(3)
	if _, err := s.PushBlob(a, id, 1, nonce(1), []byte("v1")); !errors.Is(err, ErrBlobCASMismatch) {
		t.Fatalf("expected CAS mismatch on wrong base, got %v", err)
	}
	if v, err := s.PushBlob(a, id, 0, nonce(1), []byte("v1")); err != nil || v != 1 {
		t.Fatalf("push at base 0: v=%d err=%v", v, err)
	}
	// Idempotent replay at the OLD base with the exact same push is absorbed.
	if v, err := s.PushBlob(a, id, 0, nonce(1), []byte("v1")); err != nil || v != 1 {
		t.Fatalf("idempotent replay: v=%d err=%v", v, err)
	}
	// A different push at the stale base is a real conflict.
	if _, err := s.PushBlob(a, id, 0, nonce(2), []byte("v2")); !errors.Is(err, ErrBlobCASMismatch) {
		t.Fatalf("expected CAS mismatch, got %v", err)
	}
}

func TestFSStore_HeadGenesisAdvanceAndStale(t *testing.T) {
	s, _ := newFS(t)
	a := acct(4)
	var zero [HeadIDLen]byte
	if _, _, err := s.GetHead(a); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected no head, got %v", err)
	}
	h1, err := s.AdvanceHead(a, zero, []byte("head-1"))
	if err != nil {
		t.Fatalf("genesis AdvanceHead: %v", err)
	}
	// Stale prev-hash (zero again, but head exists) → CAS mismatch.
	if _, err := s.AdvanceHead(a, zero, []byte("head-2")); !errors.Is(err, ErrHeadCASMismatch) {
		t.Fatalf("expected head CAS mismatch, got %v", err)
	}
	h2, err := s.AdvanceHead(a, h1, []byte("head-2"))
	if err != nil || h2 == h1 {
		t.Fatalf("advance from h1: h2=%x err=%v", h2, err)
	}
	rec, hid, err := s.GetHead(a)
	if err != nil || hid != h2 || !bytes.Equal(rec, []byte("head-2")) {
		t.Fatalf("GetHead: rec=%q hid=%x err=%v", rec, hid, err)
	}
}

func TestFSStore_QuotaAndReclaimRemovesBody(t *testing.T) {
	s, dir := newFS(t)
	a, id := acct(5), blob(5)
	s.PutBlob(a, id, []byte("0123456789")) // 10 bytes
	if q := s.QuotaBytes(a); q != 10 {
		t.Fatalf("quota: got %d want 10", q)
	}
	if err := s.SetTombstone(a, id, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.ReclaimTombstone(a, id); err != nil {
		t.Fatal(err)
	}
	if q := s.QuotaBytes(a); q != 0 {
		t.Fatalf("quota after reclaim: got %d want 0", q)
	}
	// L2 reclamation must remove the ciphertext body from disk (not just a marker).
	if _, err := os.Stat(s.blobPath(a, id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reclaimed body still on disk at %s", s.blobPath(a, id))
	}
	// The tombstone record survives; floor advances.
	if _, _, reclaimed, ok := s.TombstoneRecord(a, id); !ok || !reclaimed {
		t.Fatalf("tombstone record lost after reclaim")
	}
	_ = dir
}

func TestFSStore_ChangedSinceOrderedAndCursor(t *testing.T) {
	s, _ := newFS(t)
	a := acct(6)
	for i := byte(1); i <= 3; i++ {
		if _, err := s.PushBlob(a, blob(i), 0, nonce(i), []byte{i}); err != nil {
			t.Fatal(err)
		}
	}
	metas, cur := s.ChangedSince(a, 0, 2)
	if len(metas) != 2 || cur == 0 {
		t.Fatalf("ChangedSince page: n=%d cur=%d", len(metas), cur)
	}
	rest, cur2 := s.ChangedSince(a, cur, 10)
	if len(rest) != 1 || cur2 <= cur {
		t.Fatalf("ChangedSince rest: n=%d cur2=%d", len(rest), cur2)
	}
}

// TestFSStore_DurabilityReload is the load-bearing FS test: state written by one
// FSStore must survive a process restart (a fresh FSStore on the same dir). This
// is what makes backup = volume snapshot and migration = move-the-dir meaningful.
func TestFSStore_DurabilityReload(t *testing.T) {
	dir := t.TempDir()
	a, id := acct(7), blob(7)
	dev := ids.DeviceID{0xDD}
	var zero [HeadIDLen]byte
	{
		s, err := NewFSStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		s.PushBlob(a, id, 0, nonce(9), []byte("durable"))
		s.PushBlob(a, id, 1, nonce(9), []byte("durable-2"))
		s.AdvanceHead(a, zero, []byte("the-head"))
		s.AckCursor(a, dev, 5)
		s.SetTombstone(a, blob(0x77), 3)
		s.SetMeta(a, []byte("vault-meta-blob"))
	}
	// Reopen — everything must reload from disk.
	s2, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got, v, err := s2.GetBlob(a, id); err != nil || v != 2 || !bytes.Equal(got, []byte("durable-2")) {
		t.Fatalf("blob did not survive reload: %q v=%d err=%v", got, v, err)
	}
	if _, _, err := s2.GetHead(a); err != nil {
		t.Fatalf("head did not survive reload: %v", err)
	}
	if c := s2.DeviceCursor(a, dev); c != 5 {
		t.Fatalf("cursor did not survive reload: %d", c)
	}
	if fv, _, _, ok := s2.TombstoneRecord(a, blob(0x77)); !ok || fv != 3 {
		t.Fatalf("tombstone did not survive reload: fv=%d ok=%v", fv, ok)
	}
	if m, err := s2.GetMeta(a); err != nil || !bytes.Equal(m, []byte("vault-meta-blob")) {
		t.Fatalf("meta did not survive reload: %q err=%v", m, err)
	}
}

// TestFSStore_NoStaleTempFiles asserts the atomic-write path leaves no .tmp files
// behind (write-temp + rename, temp cleaned on success).
func TestFSStore_NoStaleTempFiles(t *testing.T) {
	s, dir := newFS(t)
	a := acct(8)
	for i := byte(1); i <= 5; i++ {
		s.PushBlob(a, blob(i), 0, nonce(i), []byte("x"))
	}
	s.AdvanceHead(a, [HeadIDLen]byte{}, []byte("h"))
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			if name := filepath.Base(p); len(name) >= 4 && name[:4] == ".tmp" {
				t.Fatalf("stale temp file left behind: %s", p)
			}
		}
		return nil
	})
}

// TestFSStore_WriteFailureIsCleanReject simulates a failed body write (read-only
// blobs dir, a proxy for ENOSPC): the push must be rejected cleanly with no state
// change — the prior blob intact, quota unchanged, version not advanced (SYNC-23
// graceful ENOSPC + atomic-rename: old-or-new-never-partial).
func TestFSStore_WriteFailureIsCleanReject(t *testing.T) {
	s, dir := newFS(t)
	a, id := acct(0x0A), blob(0x0A)
	if _, err := s.PutBlob(a, id, []byte("good")); err != nil {
		t.Fatal(err)
	}
	blobsDir := filepath.Join(dir, hex.EncodeToString(a[:]), "blobs")
	if err := os.Chmod(blobsDir, 0o500); err != nil {
		t.Skipf("cannot chmod to simulate write failure: %v", err)
	}
	defer func() { _ = os.Chmod(blobsDir, 0o700) }() // restore for cleanup

	// A new blob's body write must fail; the store must reject cleanly.
	if _, err := s.PutBlob(a, blob(0x0B), []byte("nope")); err == nil {
		t.Fatalf("expected write failure, got nil error")
	}
	// Prior state intact: existing blob readable, quota unchanged, no phantom entry.
	if got, v, err := s.GetBlob(a, id); err != nil || v != 1 || !bytes.Equal(got, []byte("good")) {
		t.Fatalf("prior blob corrupted after failed write: %q v=%d err=%v", got, v, err)
	}
	if q := s.QuotaBytes(a); q != 4 {
		t.Fatalf("quota changed after failed write: got %d want 4", q)
	}
	if _, _, err := s.GetBlob(a, blob(0x0B)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("phantom entry for failed-write blob: %v", err)
	}
}

var _ BlobStore = (*FSStore)(nil)
