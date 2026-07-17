// SPDX-License-Identifier: AGPL-3.0

package store

import (
	"bytes"
	"errors"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func acct(b byte) ids.AccountNumberHash {
	var a ids.AccountNumberHash
	for i := range a {
		a[i] = b
	}
	return a
}

func blob(b byte) ids.BlobID {
	var id ids.BlobID
	for i := range id {
		id[i] = b
	}
	return id
}

func TestMemStore_PutGetRoundTrip(t *testing.T) {
	s := NewMemStore()
	a := acct(0x01)
	id := blob(0xAA)
	ct := []byte("opaque-ciphertext")

	if _, err := s.PutBlob(a, id, ct); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	got, _, err := s.GetBlob(a, id)
	if err != nil {
		t.Fatalf("GetBlob: %v", err)
	}
	if !bytes.Equal(got, ct) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, ct)
	}
}

func TestMemStore_VaultIsolation(t *testing.T) {
	s := NewMemStore()
	id := blob(0xAA)
	if _, err := s.PutBlob(acct(0x01), id, []byte("a1")); err != nil {
		t.Fatal(err)
	}
	// A different account must not see account 0x01's blob, even with the same blobID.
	if _, _, err := s.GetBlob(acct(0x02), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-vault read leaked: err=%v (want ErrNotFound)", err)
	}
}

func TestMemStore_GetMissing(t *testing.T) {
	s := NewMemStore()
	if _, _, err := s.GetBlob(acct(0x09), blob(0x09)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

// F2: the reclaimed record with the highest change-sequence must be omitted
// from the metas, yet the returned cursor must advance ACROSS it — a cursor
// stalled below the reclaim floor 410s every later incremental pull.
func TestMemStore_ChangedSinceOmitsReclaimedButAdvancesCursor(t *testing.T) {
	s := NewMemStore()
	a := acct(0x04)
	for i := byte(1); i <= 3; i++ {
		if _, err := s.PushBlob(a, blob(i), 0, nonce(i), []byte{i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetTombstone(a, blob(3), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.ReclaimTombstone(a, blob(3)); err != nil {
		t.Fatal(err)
	}
	metas, cur := s.ChangedSince(a, 0, 10)
	if len(metas) != 2 || metas[0].BlobID != blob(1) || metas[1].BlobID != blob(2) {
		t.Fatalf("reclaimed record leaked into ChangedSince: %+v", metas)
	}
	if cur != 3 {
		t.Fatalf("cursor = %d, want 3 (must advance across the reclaimed record)", cur)
	}
	// A window holding ONLY the reclaimed record: empty page, moving cursor.
	empty, cur2 := s.ChangedSince(a, 2, 10)
	if len(empty) != 0 || cur2 != 3 {
		t.Fatalf("reclaimed-only window: n=%d cur=%d, want 0 metas + cursor 3", len(empty), cur2)
	}
}

func TestMemStore_GetBlobReclaimedErr(t *testing.T) {
	s := NewMemStore()
	a, id := acct(0x05), blob(0x05)
	if _, err := s.PushBlob(a, id, 0, nonce(1), []byte("body")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTombstone(a, id, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.ReclaimTombstone(a, id); err != nil {
		t.Fatal(err)
	}
	_, v, err := s.GetBlob(a, id)
	if !errors.Is(err, ErrReclaimed) {
		t.Fatalf("reclaimed GetBlob err = %v, want ErrReclaimed (never a live empty body)", err)
	}
	if v != 1 {
		t.Fatalf("reclaimed GetBlob version = %d, want 1", v)
	}
}

// F3: a CAS push that advances a reclaimed record's version resurrects it —
// tombstone record gone, body readable, meta back in the manifest.
func TestMemStore_PushBlobClearsReclaimedAndTombstone(t *testing.T) {
	s := NewMemStore()
	a, id := acct(0x06), blob(0x06)
	if _, err := s.PushBlob(a, id, 0, nonce(1), []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTombstone(a, id, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.ReclaimTombstone(a, id); err != nil {
		t.Fatal(err)
	}
	v2, err := s.PushBlob(a, id, 1, nonce(2), []byte("v2"))
	if err != nil || v2 != 2 {
		t.Fatalf("resurrection push = (%d, %v)", v2, err)
	}
	if _, _, _, ok := s.TombstoneRecord(a, id); ok {
		t.Fatal("tombstone record survived the version advance")
	}
	if ct, _, err := s.GetBlob(a, id); err != nil || string(ct) != "v2" {
		t.Fatalf("resurrected blob unreadable: %q err=%v", ct, err)
	}
	metas, _ := s.ChangedSince(a, 0, 10)
	if len(metas) != 1 || metas[0].BlobID != id {
		t.Fatalf("resurrected blob missing from the manifest: %+v", metas)
	}
}

func TestMemStore_DoesNotAliasCallerBuffer(t *testing.T) {
	s := NewMemStore()
	a, id := acct(0x03), blob(0x03)
	ct := []byte("original")
	if _, err := s.PutBlob(a, id, ct); err != nil {
		t.Fatal(err)
	}
	for i := range ct { // mutate the caller's buffer after Put
		ct[i] = 'x'
	}
	got, _, err := s.GetBlob(a, id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("original")) {
		t.Fatalf("store aliased the caller buffer: got %q", got)
	}
}
