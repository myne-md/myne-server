// SPDX-License-Identifier: AGPL-3.0

package attachments

// The fs backend's lock is per ACCOUNT, not per store. WriteAt holds it across a
// chunk write and, on the final chunk, across an fsync + rename + dir-fsync, so a
// store-wide lock would make one account's 64 MiB upload stall every other
// account's attachment traffic — the availability half of myne-server#6, applied
// to the sibling store the blob index shares its volume with.

import (
	"bytes"
	"sync"
	"testing"
)

// Uploads for distinct accounts, released together, must not interfere: every
// account ends with exactly its own bytes and its own byte total. Under -race this
// also asserts the per-account mutex discipline.
func TestConcurrent_UploadsAcrossAccountsAreIsolated(t *testing.T) {
	s, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const accounts = 8
	const perAcct = 4
	const size = 512

	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(accounts * perAcct)
	for k := 0; k < accounts*perAcct; k++ {
		go func(k int) {
			defer wg.Done()
			ai, ni := k/perAcct, k%perAcct
			a, id := acct(byte(0x80+ai)), aid(byte(ni))
			body := bytes.Repeat([]byte{byte(0x80 + ai)}, size)
			<-start
			// Two chunks, so the lock is taken and released across an append
			// as well as across the finalize.
			if err := s.WriteAt(a, id, 0, size, body[:size/2]); err != nil {
				t.Errorf("account %d chunk 0: %v", ai, err)
				return
			}
			if err := s.WriteAt(a, id, size/2, size, body[size/2:]); err != nil {
				t.Errorf("account %d chunk 1: %v", ai, err)
			}
		}(k)
	}
	close(start)
	wg.Wait()

	for ai := 0; ai < accounts; ai++ {
		a := acct(byte(0x80 + ai))
		if got := s.AccountBytes(a); got != uint64(perAcct*size) {
			t.Errorf("account %d bytes = %d, want %d (cross-account bleed)", ai, got, perAcct*size)
		}
		for ni := 0; ni < perAcct; ni++ {
			id := aid(byte(ni))
			if !s.Has(a, id) {
				t.Errorf("account %d attachment %d incomplete", ai, ni)
				continue
			}
			got, _, err := s.ReadRange(a, id, 0, size)
			if err != nil {
				t.Errorf("account %d attachment %d read: %v", ai, ni, err)
				continue
			}
			if want := bytes.Repeat([]byte{byte(0x80 + ai)}, size); !bytes.Equal(got, want) {
				t.Errorf("account %d attachment %d body mismatch", ai, ni)
			}
		}
	}
}
