// SPDX-License-Identifier: AGPL-3.0

package store

import (
	"errors"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func nonce(b byte) [ContentNonceLen]byte {
	var n [ContentNonceLen]byte
	for i := range n {
		n[i] = b
	}
	return n
}

func TestPushBlob_CAS(t *testing.T) {
	s := NewMemStore()
	a, id := acct(1), blob(1)

	// New blob requires base version 0.
	if _, err := s.PushBlob(a, id, 1, nonce(1), []byte("v1")); !errors.Is(err, ErrBlobCASMismatch) {
		t.Fatalf("new blob with base!=0 accepted: %v", err)
	}
	v1, err := s.PushBlob(a, id, 0, nonce(1), []byte("v1"))
	if err != nil || v1 != 1 {
		t.Fatalf("genesis push = (%d, %v)", v1, err)
	}
	// Stale base rejected.
	if _, err := s.PushBlob(a, id, 0, nonce(2), []byte("v2")); !errors.Is(err, ErrBlobCASMismatch) {
		t.Fatalf("stale base accepted: %v", err)
	}
	// Correct base advances.
	v2, err := s.PushBlob(a, id, 1, nonce(2), []byte("v2"))
	if err != nil || v2 != 2 {
		t.Fatalf("linear push = (%d, %v)", v2, err)
	}
	// Idempotent re-push at correct base.
	v2b, err := s.PushBlob(a, id, 1, nonce(2), []byte("v2"))
	if err != nil || v2b != 2 {
		t.Fatalf("idempotent re-push = (%d, %v), want 2", v2b, err)
	}
}

func TestChangedSince_PaginatedOrdered(t *testing.T) {
	s := NewMemStore()
	a := acct(2)
	for i := byte(1); i <= 5; i++ {
		if _, err := s.PushBlob(a, blob(i), 0, nonce(i), []byte{i}); err != nil {
			t.Fatal(err)
		}
	}
	// First page of 2 from cursor 0.
	metas, cur := s.ChangedSince(a, 0, 2)
	if len(metas) != 2 {
		t.Fatalf("page size = %d, want 2", len(metas))
	}
	// Ordered by change-sequence (ascending) → blob 1, 2.
	if metas[0].BlobID != blob(1) || metas[1].BlobID != blob(2) {
		t.Fatalf("page not ordered by change-seq")
	}
	if metas[0].ContentNonce != nonce(1) || metas[0].Size != 1 || metas[0].Version != 1 {
		t.Fatalf("sync_meta fields wrong: %+v", metas[0])
	}
	// Next page from the returned cursor → 3, 4.
	metas2, cur2 := s.ChangedSince(a, cur, 2)
	if len(metas2) != 2 || metas2[0].BlobID != blob(3) {
		t.Fatalf("second page wrong: %+v", metas2)
	}
	// Final page → 5, then empty (stable cursor).
	metas3, cur3 := s.ChangedSince(a, cur2, 2)
	if len(metas3) != 1 || metas3[0].BlobID != blob(5) {
		t.Fatalf("third page wrong: %+v", metas3)
	}
	empty, cur4 := s.ChangedSince(a, cur3, 2)
	if len(empty) != 0 || cur4 != cur3 {
		t.Fatalf("expected stable cursor at end: %d != %d (n=%d)", cur4, cur3, len(empty))
	}
}

func TestDeviceCursor_AckMonotone(t *testing.T) {
	s := NewMemStore()
	a, d := acct(3), ids.DeviceID{0xDD}
	if s.DeviceCursor(a, d) != 0 {
		t.Fatal("initial cursor != 0")
	}
	s.AckCursor(a, d, 5)
	s.AckCursor(a, d, 3) // older ignored
	if s.DeviceCursor(a, d) != 5 {
		t.Fatalf("cursor = %d, want 5 (monotone)", s.DeviceCursor(a, d))
	}
}
