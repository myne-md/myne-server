// SPDX-License-Identifier: AGPL-3.0-only

package store

import "testing"

func TestMemStore_QuotaCountsOncePerBlob(t *testing.T) {
	s := NewMemStore()
	a := acct(0x01)

	if s.QuotaBytes(a) != 0 {
		t.Fatalf("empty account quota = %d, want 0", s.QuotaBytes(a))
	}
	if _, err := s.PutBlob(a, blob(0x01), make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBlob(a, blob(0x02), make([]byte, 50)); err != nil {
		t.Fatal(err)
	}
	if got := s.QuotaBytes(a); got != 150 {
		t.Fatalf("quota after two blobs = %d, want 150", got)
	}
}

func TestMemStore_QuotaAdjustsOnSizeChangeNotPerReference(t *testing.T) {
	s := NewMemStore()
	a, id := acct(0x02), blob(0x02)

	if _, err := s.PutBlob(a, id, make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	// Idempotent re-put (same size, same bytes) must NOT double-count.
	if _, err := s.PutBlob(a, id, make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if got := s.QuotaBytes(a); got != 100 {
		t.Fatalf("quota after idempotent re-put = %d, want 100 (counted once)", got)
	}
	// New ciphertext of a different size adjusts by the delta, not adds.
	if _, err := s.PutBlob(a, id, make([]byte, 30)); err != nil {
		t.Fatal(err)
	}
	if got := s.QuotaBytes(a); got != 30 {
		t.Fatalf("quota after shrink = %d, want 30 (delta-adjusted)", got)
	}
}

func TestMemStore_TombstoneRecordRoundTrip(t *testing.T) {
	s := NewMemStore()
	a, id := acct(0x03), blob(0x03)

	if _, marked := s.Tombstone(a, id); marked {
		t.Fatal("blob marked tombstone before SetTombstone")
	}
	if err := s.SetTombstone(a, id, Version(7)); err != nil {
		t.Fatal(err)
	}
	fv, marked := s.Tombstone(a, id)
	if !marked || fv != 7 {
		t.Fatalf("tombstone record = (%d, %v), want (7, true)", fv, marked)
	}
}

// BlobQuotaBytes is the per-blob half of the counter — the bytes a push replaces,
// which is what the push gate must subtract to charge growth rather than size
// (myne-server#10). Both backends must report the same figure they net out of
// QuotaBytes, including 0 for a body horizon-GC already reclaimed.
func TestBlobQuotaBytes_IsTheBlobsShareOfTheCounter(t *testing.T) {
	fs, _ := newFS(t)
	for _, tc := range []struct {
		name string
		s    BlobStore
	}{{"mem", NewMemStore()}, {"fs", fs}} {
		t.Run(tc.name, func(t *testing.T) {
			a, id, other := acct(0x07), blob(0x07), blob(0x08)
			if got := tc.s.BlobQuotaBytes(a, id); got != 0 {
				t.Fatalf("absent blob = %d, want 0", got)
			}
			if _, err := tc.s.PushBlob(a, id, 0, [ContentNonceLen]byte{}, make([]byte, 40)); err != nil {
				t.Fatal(err)
			}
			if _, err := tc.s.PushBlob(a, other, 0, [ContentNonceLen]byte{}, make([]byte, 10)); err != nil {
				t.Fatal(err)
			}
			if got, total := tc.s.BlobQuotaBytes(a, id), tc.s.QuotaBytes(a); got != 40 || total != 50 {
				t.Fatalf("blob = %d, account = %d; want 40 of 50", got, total)
			}
			if err := tc.s.SetTombstone(a, id, 1); err != nil {
				t.Fatal(err)
			}
			if err := tc.s.ReclaimTombstone(a, id); err != nil {
				t.Fatal(err)
			}
			if got, total := tc.s.BlobQuotaBytes(a, id), tc.s.QuotaBytes(a); got != 0 || total != 10 {
				t.Fatalf("after reclaim blob = %d, account = %d; want 0 of 10", got, total)
			}
		})
	}
}
