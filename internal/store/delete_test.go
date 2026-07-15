// SPDX-License-Identifier: AGPL-3.0

package store

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func acctH(b byte) ids.AccountNumberHash {
	var a ids.AccountNumberHash
	a[0] = b
	return a
}
func blobH(b byte) ids.BlobID {
	var x ids.BlobID
	x[0] = b
	return x
}

func TestDeleteAccount_MemStore(t *testing.T) {
	s := NewMemStore()
	a := acctH(1)
	if _, err := s.PutBlob(a, blobH(1), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if len(s.ListAccounts()) != 1 {
		t.Fatalf("want 1 account before delete")
	}
	if err := s.DeleteAccount(a); err != nil {
		t.Fatal(err)
	}
	if len(s.ListAccounts()) != 0 {
		t.Errorf("account still present after delete")
	}
	if s.QuotaBytes(a) != 0 {
		t.Errorf("quota not cleared after delete: %d", s.QuotaBytes(a))
	}
	// Idempotent.
	if err := s.DeleteAccount(a); err != nil {
		t.Errorf("delete of a missing account should be a no-op, got %v", err)
	}
}

func TestDeleteAccount_FSStore(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := acctH(0xAB)
	if _, err := s.PutBlob(a, blobH(1), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	vaultDir := filepath.Join(dir, hex.EncodeToString(a[:]))
	if _, err := os.Stat(vaultDir); err != nil {
		t.Fatalf("vault dir should exist before delete: %v", err)
	}
	if err := s.DeleteAccount(a); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(vaultDir); !os.IsNotExist(err) {
		t.Errorf("vault dir should be removed, stat err = %v", err)
	}
	if len(s.ListAccounts()) != 0 {
		t.Errorf("account still in ListAccounts after delete")
	}
}
