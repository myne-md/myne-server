// SPDX-License-Identifier: AGPL-3.0-only

package store

// Crash-consistency / fault-injection durability for the FS backend. The existing
// suite covers a single-state reload, no-stale-temps, and a clean reject on a failed
// write. These add the harder crash scenarios the atomic-write design must survive:
//
//   - power loss at every step boundary of a rich sequence (a filesystem snapshot of
//     the store dir reopens cleanly and is internally consistent);
//   - a crash between atomicWrite's temp-create and its rename (a stray .tmp-* file in
//     a blobs dir is tolerated on reopen, never surfaced as a blob);
//   - a crash AFTER a blob body is written but BEFORE the index persists (PushBlob
//     writes the body first, so the index — the source of truth — must ignore the
//     resulting orphan body and stay consistent).

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

// assertConsistent checks an FS store's public-API self-consistency: every blob the
// index reports (via ChangedSince) has a readable body whose version and size match
// the meta, and QuotaBytes equals the summed live-body size.
func assertConsistent(t *testing.T, s BlobStore, accts []ids.AccountNumberHash, tag string) {
	t.Helper()
	for _, a := range accts {
		metas, _ := s.ChangedSince(a, 0, 0) // limit 0 = all
		var sum uint64
		for _, m := range metas {
			body, v, err := s.GetBlob(a, m.BlobID)
			if err != nil {
				t.Fatalf("%s: blob %#x in index but body unreadable: %v", tag, m.BlobID[0], err)
			}
			if v != m.Version {
				t.Fatalf("%s: version index=%d body=%d", tag, m.Version, v)
			}
			if len(body) != m.Size {
				t.Fatalf("%s: size index=%d body=%d", tag, m.Size, len(body))
			}
			sum += uint64(len(body))
		}
		if q := s.QuotaBytes(a); q != sum {
			t.Fatalf("%s: quota %d != summed live-body size %d", tag, q, sum)
		}
	}
}

func TestFSStore_CrashSnapshotConsistencyAcrossSequence(t *testing.T) {
	dir := t.TempDir()
	snapRoot := t.TempDir()
	s, err := NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	accts := []ids.AccountNumberHash{acct(1), acct(2)}

	// A varied sequence touching every persistence path: push, version bump, head
	// advance, second account, meta, cursor, tombstone, reclaim.
	ops := []func(){
		func() { s.PushBlob(accts[0], blob(1), 0, nonce(1), []byte("a-blob-1")) },
		func() { s.PushBlob(accts[0], blob(1), 1, nonce(2), []byte("a-blob-1-v2-longer")) },
		func() { s.AdvanceHead(accts[0], [HeadIDLen]byte{}, []byte("a-head-1")) },
		func() { s.PushBlob(accts[0], blob(2), 0, nonce(3), []byte("a-blob-2")) },
		func() { s.PushBlob(accts[1], blob(1), 0, nonce(4), []byte("b-blob-1")) },
		func() { s.SetMeta(accts[1], []byte("b-vault-meta")) },
		func() { s.AckCursor(accts[0], deviceID(1), 3) },
		func() { s.SetTombstone(accts[0], blob(2), 2) },
		func() { _ = s.ReclaimTombstone(accts[0], blob(2)) },
		func() { s.AdvanceHead(accts[1], [HeadIDLen]byte{}, []byte("b-head-1")) },
	}

	var snaps []string
	for i, op := range ops {
		op()
		sd := filepath.Join(snapRoot, fmt.Sprintf("snap-%02d", i))
		if err := copyTree(dir, sd); err != nil {
			t.Fatalf("snapshot %d: %v", i, err)
		}
		snaps = append(snaps, sd)
	}

	// Every step-boundary snapshot reopens cleanly and is internally consistent — no
	// half-committed state is ever visible at a boundary.
	for _, sd := range snaps {
		s2, err := NewFSStore(sd)
		if err != nil {
			t.Fatalf("reopen snapshot %s: %v", sd, err)
		}
		assertConsistent(t, s2, accts, filepath.Base(sd))
	}
}

func TestFSStore_ReopenToleratesStrayTempFile(t *testing.T) {
	s, dir := newFS(t)
	a := acct(3)
	if _, err := s.PushBlob(a, blob(1), 0, nonce(1), []byte("real-blob")); err != nil {
		t.Fatal(err)
	}
	before, _ := s.ChangedSince(a, 0, 0)

	// A crash between atomicWrite's temp-create and rename leaves a .tmp-* file in the
	// target dir. Plant one in the blobs dir and one in the vault dir (index/head temp).
	vaultDir := filepath.Join(dir, hex.EncodeToString(a[:]))
	for _, p := range []string{
		filepath.Join(vaultDir, "blobs", ".tmp-crashed-body"),
		filepath.Join(vaultDir, ".tmp-crashed-index"),
	} {
		if err := os.WriteFile(p, []byte("half-written-garbage"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	s2, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("reopen with stray temp files: %v", err)
	}
	if after, _ := s2.ChangedSince(a, 0, 0); len(after) != len(before) {
		t.Fatalf("stray temp surfaced as a blob: before=%d after=%d", len(before), len(after))
	}
	if body, v, err := s2.GetBlob(a, blob(1)); err != nil || v != 1 || !bytes.Equal(body, []byte("real-blob")) {
		t.Fatalf("real blob not intact after reopen: %q v=%d err=%v", body, v, err)
	}
	if _, err := s2.PushBlob(a, blob(2), 0, nonce(2), []byte("post-recovery")); err != nil {
		t.Fatalf("write after recovery failed: %v", err)
	}
}

func TestFSStore_ReopenIgnoresOrphanBody(t *testing.T) {
	s, dir := newFS(t)
	a := acct(4)
	if _, err := s.PushBlob(a, blob(1), 0, nonce(1), []byte("committed")); err != nil {
		t.Fatal(err)
	}
	before, _ := s.ChangedSince(a, 0, 0)
	quotaBefore := s.QuotaBytes(a)

	// A crash AFTER the body atomicWrite but BEFORE the index persist leaves a body on
	// disk the index never references (PushBlob writes body-first).
	orphan := blob(2)
	orphanPath := filepath.Join(dir, hex.EncodeToString(a[:]), "blobs", hex.EncodeToString(orphan[:]))
	if err := os.WriteFile(orphanPath, []byte("orphan-body-from-crash"), 0o600); err != nil {
		t.Fatal(err)
	}

	s2, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("reopen with orphan body: %v", err)
	}
	// The index is the source of truth: the orphan is invisible and uncounted.
	if _, _, err := s2.GetBlob(a, orphan); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan body surfaced via GetBlob: %v", err)
	}
	if after, _ := s2.ChangedSince(a, 0, 0); len(after) != len(before) {
		t.Fatalf("orphan body surfaced in ChangedSince: before=%d after=%d", len(before), len(after))
	}
	if q := s2.QuotaBytes(a); q != quotaBefore {
		t.Fatalf("orphan body affected quota: got %d want %d", q, quotaBefore)
	}
	// The committed blob is intact, and the orphan id is cleanly writable.
	if body, _, err := s2.GetBlob(a, blob(1)); err != nil || !bytes.Equal(body, []byte("committed")) {
		t.Fatalf("committed blob not intact: %q err=%v", body, err)
	}
	if _, err := s2.PushBlob(a, orphan, 0, nonce(2), []byte("now-committed")); err != nil {
		t.Fatalf("pushing over orphan id failed: %v", err)
	}
}
