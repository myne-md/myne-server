// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestMemStore_GenesisHeadThenAdvance(t *testing.T) {
	s := NewMemStore()
	a := acct(0x01)
	var zero [HeadIDLen]byte

	if _, _, err := s.GetHead(a); !errors.Is(err, ErrNotFound) {
		t.Fatalf("head before genesis: %v, want ErrNotFound", err)
	}

	rec1 := []byte("opaque-head-record-1")
	id1, err := s.AdvanceHead(a, zero, rec1) // genesis: prev = zero
	if err != nil {
		t.Fatalf("genesis AdvanceHead: %v", err)
	}
	if id1 != sha256.Sum256(rec1) {
		t.Fatalf("head_id != SHA-256(record)")
	}

	// Subsequent advance with the correct prev (id1) succeeds.
	rec2 := []byte("opaque-head-record-2")
	id2, err := s.AdvanceHead(a, id1, rec2)
	if err != nil {
		t.Fatalf("linear AdvanceHead: %v", err)
	}
	if id2 != sha256.Sum256(rec2) {
		t.Fatalf("head_id2 != SHA-256(record2)")
	}

	gotRec, gotID, err := s.GetHead(a)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != id2 || !bytes.Equal(gotRec, rec2) {
		t.Fatalf("GetHead returned the wrong current head")
	}
}

func TestMemStore_StalePrevHashRejected(t *testing.T) {
	s := NewMemStore()
	a := acct(0x02)
	var zero [HeadIDLen]byte

	id1, err := s.AdvanceHead(a, zero, []byte("rec1"))
	if err != nil {
		t.Fatal(err)
	}
	_ = id1
	// A stale prev (zero again, or any wrong hash) must be rejected — a fork the
	// server must not accept.
	if _, err := s.AdvanceHead(a, zero, []byte("rec2-fork")); !errors.Is(err, ErrHeadCASMismatch) {
		t.Fatalf("stale prev accepted: %v, want ErrHeadCASMismatch", err)
	}
	var wrong [HeadIDLen]byte
	wrong[0] = 0xFF
	if _, err := s.AdvanceHead(a, wrong, []byte("rec2-fork")); !errors.Is(err, ErrHeadCASMismatch) {
		t.Fatalf("wrong prev accepted: %v, want ErrHeadCASMismatch", err)
	}
}

func TestMemStore_GenesisRejectedWhenHeadExists(t *testing.T) {
	s := NewMemStore()
	a := acct(0x03)
	var zero [HeadIDLen]byte
	if _, err := s.AdvanceHead(a, zero, []byte("rec1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdvanceHead(a, zero, []byte("rec2")); !errors.Is(err, ErrHeadCASMismatch) {
		t.Fatalf("second genesis accepted: %v, want ErrHeadCASMismatch", err)
	}
}

func TestMemStore_HeadStoredOpaquely(t *testing.T) {
	// The server stores arbitrary bytes as the head and never parses them.
	s := NewMemStore()
	a := acct(0x04)
	var zero [HeadIDLen]byte
	rec := []byte{0x00, 0xFF, 0x10, 0x42, 0x00} // not valid utf8 / arbitrary
	id, err := s.AdvanceHead(a, zero, rec)
	if err != nil {
		t.Fatal(err)
	}
	got, gotID, err := s.GetHead(a)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != id || !bytes.Equal(got, rec) {
		t.Fatalf("opaque head round-trip failed")
	}
}
