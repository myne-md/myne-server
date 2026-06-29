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
