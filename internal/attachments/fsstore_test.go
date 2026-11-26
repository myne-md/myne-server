// SPDX-License-Identifier: AGPL-3.0-only

package attachments

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func acct(b byte) ids.AccountNumberHash {
	var a ids.AccountNumberHash
	a[0] = b
	return a
}

// backends runs a conformance subtest against BOTH implementations — the
// deleted-is-absent + re-add + reclaim semantics must not diverge between the
// dev/E2E reference and the production fs backend (MYND-468).
func backends(t *testing.T, run func(t *testing.T, s Backend)) {
	t.Helper()
	t.Run("mem", func(t *testing.T) { run(t, NewStore()) })
	t.Run("fs", func(t *testing.T) {
		s, err := NewFSStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		run(t, s)
	})
}

func TestBackend_WriteReadRoundTrip(t *testing.T) {
	backends(t, func(t *testing.T, s Backend) {
		a, id := acct(1), aid(1)
		body := []byte("attachment ciphertext body")
		if err := s.WriteAt(a, id, 0, len(body), body); err != nil {
			t.Fatal(err)
		}
		if !s.Has(a, id) {
			t.Fatal("complete upload must be present")
		}
		chunk, total, err := s.ReadRange(a, id, 0, 0)
		if err != nil || total != len(body) || !bytes.Equal(chunk, body) {
			t.Fatalf("ReadRange = (%q, %d, %v), want the full body", chunk, total, err)
		}
		// A middle range.
		chunk, _, err = s.ReadRange(a, id, 11, 10)
		if err != nil || string(chunk) != "ciphertext" {
			t.Fatalf("range read = (%q, %v)", chunk, err)
		}
		if got := s.AccountBytes(a); got != uint64(len(body)) {
			t.Fatalf("AccountBytes = %d, want %d", got, len(body))
		}
	})
}

func TestBackend_SequentialResume(t *testing.T) {
	backends(t, func(t *testing.T, s Backend) {
		a, id := acct(2), aid(2)
		if err := s.WriteAt(a, id, 0, 6, []byte("abc")); err != nil {
			t.Fatal(err)
		}
		if n, known := s.UploadedLen(a, id); !known || n != 3 {
			t.Fatalf("UploadedLen = (%d, %v), want (3, true)", n, known)
		}
		if s.Has(a, id) {
			t.Fatal("half-uploaded id must not read complete")
		}
		// Wrong offset → ErrBadOffset (the client re-probes).
		if err := s.WriteAt(a, id, 1, 6, []byte("xyz")); err != ErrBadOffset {
			t.Fatalf("bad offset = %v, want ErrBadOffset", err)
		}
		if err := s.WriteAt(a, id, 3, 6, []byte("def")); err != nil {
			t.Fatal(err)
		}
		if !s.Has(a, id) {
			t.Fatal("upload must complete at total")
		}
		chunk, _, _ := s.ReadRange(a, id, 0, 0)
		if string(chunk) != "abcdef" {
			t.Fatalf("assembled = %q", chunk)
		}
	})
}

func TestBackend_MarkDeletedIsAbsentAndReAddRestarts(t *testing.T) {
	backends(t, func(t *testing.T, s Backend) {
		a, id := acct(3), aid(3)
		if err := s.WriteAt(a, id, 0, 3, []byte("old")); err != nil {
			t.Fatal(err)
		}
		s.MarkDeleted(a, id)
		// §11.4 deleted-is-absent: HEAD/GET probes read as unknown.
		if s.Has(a, id) {
			t.Fatal("deleted id must not read complete")
		}
		if _, known := s.UploadedLen(a, id); known {
			t.Fatal("deleted id must read unknown")
		}
		if _, _, err := s.ReadRange(a, id, 0, 0); err != ErrNotFound {
			t.Fatalf("deleted read = %v, want ErrNotFound", err)
		}
		// Bytes keep counting until Reclaim (retention symmetry with notes).
		if got := s.AccountBytes(a); got != 3 {
			t.Fatalf("AccountBytes after MarkDeleted = %d, want 3", got)
		}
		// A PUT to the deleted id is the §11.4 re-add: fresh upload from zero.
		if err := s.WriteAt(a, id, 0, 5, []byte("fresh")); err != nil {
			t.Fatalf("re-add write = %v", err)
		}
		if !s.Has(a, id) {
			t.Fatal("re-added id must be present")
		}
		chunk, _, _ := s.ReadRange(a, id, 0, 0)
		if string(chunk) != "fresh" {
			t.Fatalf("re-added body = %q", chunk)
		}
		if got := s.AccountBytes(a); got != 5 {
			t.Fatalf("AccountBytes after re-add = %d, want 5 (old bytes released)", got)
		}
	})
}

func TestBackend_ReclaimFreesBytesAndSlot(t *testing.T) {
	backends(t, func(t *testing.T, s Backend) {
		a, id := acct(4), aid(4)
		if err := s.WriteAt(a, id, 0, 4, []byte("body")); err != nil {
			t.Fatal(err)
		}
		s.MarkDeleted(a, id)
		freed, ok := s.Reclaim(a, id)
		if !ok || freed != 4 {
			t.Fatalf("Reclaim = (%d, %v), want (4, true)", freed, ok)
		}
		if got := s.AccountBytes(a); got != 0 {
			t.Fatalf("AccountBytes after reclaim = %d, want 0", got)
		}
		// Unknown id → ok=false.
		if _, ok := s.Reclaim(a, id); ok {
			t.Fatal("double reclaim must report ok=false")
		}
		// The slot is free again: a fresh upload of the same id succeeds.
		if err := s.WriteAt(a, id, 0, 2, []byte("re")); err != nil {
			t.Fatalf("post-reclaim re-upload = %v", err)
		}
	})
}

// --- FS durability (the restart-shaped behaviors the mem store cannot pin) ---

func reopen(t *testing.T, root string) *FSStore {
	t.Helper()
	s, err := NewFSStore(root)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFSStore_RestartResumesFromPartialAndRebuildsQuota(t *testing.T) {
	root := t.TempDir()
	s := reopen(t, root)
	a, id := acct(5), aid(5)
	if err := s.WriteAt(a, id, 0, 6, []byte("abc")); err != nil {
		t.Fatal(err)
	}

	// "Restart": a fresh store over the same root. The partial's FILE SIZE is
	// the resume offset; the quota counter rebuilds from disk.
	s2 := reopen(t, root)
	if n, known := s2.UploadedLen(a, id); !known || n != 3 {
		t.Fatalf("post-restart UploadedLen = (%d, %v), want (3, true)", n, known)
	}
	if got := s2.AccountBytes(a); got != 3 {
		t.Fatalf("post-restart AccountBytes = %d, want 3 (rebuilt from disk)", got)
	}
	if err := s2.WriteAt(a, id, 3, 6, []byte("def")); err != nil {
		t.Fatalf("post-restart resume = %v", err)
	}
	if !s2.Has(a, id) {
		t.Fatal("resumed upload must complete")
	}
	chunk, _, _ := s2.ReadRange(a, id, 0, 0)
	if string(chunk) != "abcdef" {
		t.Fatalf("assembled after restart = %q", chunk)
	}
}

func TestFSStore_TornAppendSelfHealsToFileSize(t *testing.T) {
	root := t.TempDir()
	s := reopen(t, root)
	a, id := acct(6), aid(6)
	if err := s.WriteAt(a, id, 0, 8, []byte("abcd")); err != nil {
		t.Fatal(err)
	}
	// Simulate a torn append (no per-chunk fsync): the tail of the partial is
	// lost in a crash. The file is the authority on reopen.
	partial := filepath.Join(root, hex.EncodeToString(a[:]), "attachments", hex.EncodeToString(id[:])+".partial")
	if err := os.Truncate(partial, 2); err != nil {
		t.Fatal(err)
	}
	s2 := reopen(t, root)
	if n, known := s2.UploadedLen(a, id); !known || n != 2 {
		t.Fatalf("post-torn UploadedLen = (%d, %v), want (2, true)", n, known)
	}
	// Resume from the REAL size completes correctly.
	if err := s2.WriteAt(a, id, 2, 8, []byte("cdefgh")); err != nil {
		t.Fatalf("resume after torn append = %v", err)
	}
	chunk, _, _ := s2.ReadRange(a, id, 0, 0)
	if string(chunk) != "abcdefgh" {
		t.Fatalf("assembled = %q", chunk)
	}
}

func TestFSStore_FinalizeOnLoadAfterCrashBeforeRename(t *testing.T) {
	root := t.TempDir()
	s := reopen(t, root)
	a, id := acct(7), aid(7)
	// Assemble a full partial WITHOUT the rename: write 3 of 6, then simulate
	// the crash window by appending the tail directly to the partial file.
	if err := s.WriteAt(a, id, 0, 6, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(root, hex.EncodeToString(a[:]), "attachments", hex.EncodeToString(id[:])+".partial")
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("def")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	s2 := reopen(t, root)
	if !s2.Has(a, id) {
		t.Fatal("partial==total must finalize on load")
	}
	chunk, _, _ := s2.ReadRange(a, id, 0, 0)
	if string(chunk) != "abcdef" {
		t.Fatalf("finalized body = %q", chunk)
	}
}

func TestFSStore_IndexDriftEntryWithoutFileIsDropped(t *testing.T) {
	root := t.TempDir()
	s := reopen(t, root)
	a, id := acct(8), aid(8)
	if err := s.WriteAt(a, id, 0, 4, []byte("body")); err != nil {
		t.Fatal(err)
	}
	// Drop the body behind the store's back (drift).
	final := filepath.Join(root, hex.EncodeToString(a[:]), "attachments", hex.EncodeToString(id[:]))
	if err := os.Remove(final); err != nil {
		t.Fatal(err)
	}
	s2 := reopen(t, root)
	if s2.Has(a, id) {
		t.Fatal("index entry without a file must be dropped on load")
	}
	if got := s2.AccountBytes(a); got != 0 {
		t.Fatalf("AccountBytes after drift-drop = %d, want 0", got)
	}
}

func TestFSStore_DeletedSurvivesRestartAndReclaimDropsFiles(t *testing.T) {
	root := t.TempDir()
	s := reopen(t, root)
	a, id := acct(9), aid(9)
	if err := s.WriteAt(a, id, 0, 4, []byte("body")); err != nil {
		t.Fatal(err)
	}
	s.MarkDeleted(a, id)

	// The deleted-is-absent state survives a restart (ExtendedRetention shape:
	// the body is retained on disk but hidden).
	s2 := reopen(t, root)
	if s2.Has(a, id) {
		t.Fatal("deleted mark must survive restart")
	}
	final := filepath.Join(root, hex.EncodeToString(a[:]), "attachments", hex.EncodeToString(id[:]))
	if _, err := os.Stat(final); err != nil {
		t.Fatal("body must still be on disk until reclaim")
	}
	freed, ok := s2.Reclaim(a, id)
	if !ok || freed != 4 {
		t.Fatalf("Reclaim = (%d, %v), want (4, true)", freed, ok)
	}
	if _, err := os.Stat(final); !os.IsNotExist(err) {
		t.Fatal("reclaim must physically remove the body")
	}
	// And the reclaim outlives another restart.
	s3 := reopen(t, root)
	if _, known := s3.UploadedLen(a, id); known {
		t.Fatal("reclaimed id must stay unknown after restart")
	}
	if got := s3.AccountBytes(a); got != 0 {
		t.Fatalf("AccountBytes after reclaim+restart = %d, want 0", got)
	}
}

func TestFSStore_IDCapCountsPartialsAcrossRestart(t *testing.T) {
	root := t.TempDir()
	s, err := NewFSStore(root)
	if err != nil {
		t.Fatal(err)
	}
	s = s.WithMaxIDs(2)
	a := acct(10)
	// Two half-finished uploads occupy both slots.
	if err := s.WriteAt(a, aid(1), 0, 4, []byte("ab")); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteAt(a, aid(2), 0, 4, []byte("cd")); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteAt(a, aid(3), 0, 4, []byte("ef")); err != ErrTooManyAttachments {
		t.Fatalf("third id = %v, want ErrTooManyAttachments", err)
	}
	// The cap holds across a restart (persisted upload-start state).
	s2 := reopen(t, root).WithMaxIDs(2)
	if err := s2.WriteAt(a, aid(3), 0, 4, []byte("ef")); err != ErrTooManyAttachments {
		t.Fatalf("post-restart third id = %v, want ErrTooManyAttachments", err)
	}
}
