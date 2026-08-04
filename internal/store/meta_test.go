// SPDX-License-Identifier: AGPL-3.0

package store

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A failed vault.meta write must SAY so, like every other durable mutation on
// this backend. The meta is the enrollment bootstrap, and a device treats the
// PUT's success as "published": it clears its dirty marker and pins the uploaded
// meta as its baseline. So swallowing the error does not merely drop the upload —
// the next cycle reads the stale server copy as an authoritative remote change
// and reverts the password change this meta carried.
func TestFSStore_SetMetaReportsWriteFailure(t *testing.T) {
	t.Run("meta body write fails", func(t *testing.T) {
		s, dir := newFS(t)
		a := acct(0x21)
		if err := s.SetMeta(a, []byte("meta-v1")); err != nil {
			t.Fatalf("precondition: first SetMeta: %v", err)
		}
		// Occupy the meta path with a directory: rename(2) onto it fails for every
		// uid, so this simulation still bites under CI's root container (unlike the
		// read-only-dir trick, which root walks straight through).
		metaPath := filepath.Join(dir, hex.EncodeToString(a[:]), "meta")
		if err := os.Remove(metaPath); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(metaPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := s.SetMeta(a, []byte("meta-v2")); err == nil {
			t.Fatal("SetMeta returned nil for a meta it never wrote")
		}
	})

	t.Run("index write fails", func(t *testing.T) {
		s, _ := newFS(t)
		a := acct(0x22)
		boom := errors.New("simulated index write failure")
		s.writeIndex = func(string, []byte) error { return boom }
		if err := s.SetMeta(a, []byte("meta-v1")); !errors.Is(err, boom) {
			t.Fatalf("SetMeta err = %v, want %v", err, boom)
		}
	})

	// The tombstoned-vault refusal is reachable only by a caller that resolved the
	// vault pointer BEFORE DeleteAccount dropped it from the map (one that arrives
	// afterwards gets a fresh vault from vaultFor). Re-registering the tombstoned
	// pointer is how that in-flight caller's view is reconstructed without a racy
	// goroutine handoff — the `deleted` flag itself is set by DeleteAccount, not here.
	t.Run("account deleted mid-write", func(t *testing.T) {
		s, dir := newFS(t)
		a := acct(0x23)
		if err := s.SetMeta(a, []byte("meta-v1")); err != nil {
			t.Fatal(err)
		}
		v := s.lookupVault(a)
		if err := s.DeleteAccount(a); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.vaults[a] = v
		s.mu.Unlock()

		if err := s.SetMeta(a, []byte("meta-v2")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("SetMeta on a tombstoned vault: err = %v, want ErrNotFound", err)
		}
		if _, err := os.Stat(filepath.Join(dir, hex.EncodeToString(a[:]))); !os.IsNotExist(err) {
			t.Fatalf("deleted vault dir came back: stat err = %v", err)
		}
	})
}
