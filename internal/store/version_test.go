// SPDX-License-Identifier: AGPL-3.0

package store

import (
	"errors"
	"testing"
)

func TestMemStore_VersionMonotonic(t *testing.T) {
	s := NewMemStore()
	a, id := acct(0x01), blob(0x01)

	v1, err := s.PutBlob(a, id, []byte("v1"))
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.PutBlob(a, id, []byte("v2-changed"))
	if err != nil {
		t.Fatal(err)
	}
	v3, err := s.PutBlob(a, id, []byte("v3-changed"))
	if err != nil {
		t.Fatal(err)
	}
	if !(v1 < v2 && v2 < v3) {
		t.Fatalf("version not strictly monotonic on new ciphertext: %d, %d, %d", v1, v2, v3)
	}
	// First version is a small counter value, not a wall-clock-derived number.
	if v1 != 1 {
		t.Fatalf("first version = %d, want 1 (a counter, not a timestamp)", v1)
	}
}

func TestMemStore_IdempotentRePut(t *testing.T) {
	s := NewMemStore()
	a, id := acct(0x02), blob(0x02)

	v1, err := s.PutBlob(a, id, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.PutBlob(a, id, []byte("same")) // byte-identical re-put
	if err != nil {
		t.Fatal(err)
	}
	if v1 != v2 {
		t.Fatalf("idempotent re-put advanced version: %d -> %d", v1, v2)
	}
}

func TestMemStore_BlobVersionIsCASBase(t *testing.T) {
	s := NewMemStore()
	a, id := acct(0x03), blob(0x03)

	if _, err := s.BlobVersion(a, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("version of absent blob: %v, want ErrNotFound", err)
	}
	put, _ := s.PutBlob(a, id, []byte("x"))
	got, err := s.BlobVersion(a, id)
	if err != nil {
		t.Fatal(err)
	}
	if got != put {
		t.Fatalf("BlobVersion %d != Put-returned %d", got, put)
	}
}
