// SPDX-License-Identifier: AGPL-3.0-or-later

package store

// Concurrency stress tests for the blind blob store. The existing *_test.go suites
// exercise each operation single-threaded; these drive the same operations from many
// goroutines released simultaneously to pin the load-bearing invariants under
// contention: optimistic-CAS exclusivity (PushBlob), head pointer-CAS exclusivity
// (AdvanceHead), idempotent-replay absorption (SYNC-5), quota accounting with no
// lost-update, cursor monotonicity, and per-vault isolation. Run under `-race` they
// also assert the mutex discipline of both backends (MemStore + FSStore).

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

// storeFactory builds a fresh BlobStore for one subtest. Both production-shaped
// backends are exercised: the in-memory reference and the on-disk FS store.
type storeFactory struct {
	name string
	mk   func(t *testing.T) BlobStore
}

func concurrentStores() []storeFactory {
	return []storeFactory{
		{"mem", func(t *testing.T) BlobStore { return NewMemStore() }},
		{"fs", func(t *testing.T) BlobStore { s, _ := newFS(t); return s }},
	}
}

// fanOut runs fn(i) in n goroutines released at once (a start barrier concentrates
// the race window) and blocks until all return. fn may call t.Error* (concurrency-
// safe) but never t.Fatal* (illegal off the test goroutine).
func fanOut(n int, fn func(i int)) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			fn(i)
		}(i)
	}
	close(start)
	wg.Wait()
}

func deviceID(b byte) ids.DeviceID {
	var d ids.DeviceID
	d[0] = b
	return d
}

// Many racers push the SAME blob at the SAME base with DISTINCT ciphertext: exactly
// one CAS wins (version base+1), every other gets ErrBlobCASMismatch — no lost
// update, no double-advance, quota counted once for the surviving body.
func TestConcurrent_PushBlobCAS_SingleWinner(t *testing.T) {
	for _, sf := range concurrentStores() {
		t.Run(sf.name, func(t *testing.T) {
			s := sf.mk(t)
			a, id := acct(0x10), blob(0x20)
			if _, err := s.PutBlob(a, id, []byte("seed")); err != nil {
				t.Fatal(err)
			}
			base, err := s.BlobVersion(a, id)
			if err != nil {
				t.Fatal(err)
			}

			const n = 64
			var winners, mismatches atomic.Int64
			var winnerCT atomic.Value
			fanOut(n, func(i int) {
				ct := []byte(fmt.Sprintf("racer-%03d-distinct-ciphertext", i))
				v, err := s.PushBlob(a, id, base, nonce(byte(i)), ct)
				switch {
				case err == nil:
					winners.Add(1)
					winnerCT.Store(ct)
					if v != base+1 {
						t.Errorf("winner version = %d, want %d", v, base+1)
					}
				case errors.Is(err, ErrBlobCASMismatch):
					mismatches.Add(1)
				default:
					t.Errorf("unexpected push error: %v", err)
				}
			})

			if winners.Load() != 1 {
				t.Fatalf("winners = %d, want exactly 1", winners.Load())
			}
			if mismatches.Load() != n-1 {
				t.Fatalf("mismatches = %d, want %d", mismatches.Load(), n-1)
			}
			got, gotV, err := s.GetBlob(a, id)
			if err != nil {
				t.Fatal(err)
			}
			if gotV != base+1 {
				t.Fatalf("final version = %d, want %d", gotV, base+1)
			}
			wantCT := winnerCT.Load().([]byte)
			if !bytes.Equal(got, wantCT) {
				t.Fatalf("final ciphertext is not the winner's")
			}
			if qb := s.QuotaBytes(a); qb != uint64(len(wantCT)) {
				t.Fatalf("quota = %d, want %d (counted once)", qb, len(wantCT))
			}
		})
	}
}

// Many racers push the SAME (base, ciphertext, nonce): the first advances the
// version, every later replay is absorbed as idempotent (SYNC-5) — none errors, the
// version lands at exactly 1, never base+n.
func TestConcurrent_PushBlobIdempotentReplay_NoDoubleAdvance(t *testing.T) {
	for _, sf := range concurrentStores() {
		t.Run(sf.name, func(t *testing.T) {
			s := sf.mk(t)
			a, id := acct(0x11), blob(0x21)
			ct := []byte("identical-ciphertext-for-every-racer")
			nz := nonce(0x07)

			const n = 64
			var errCount atomic.Int64
			fanOut(n, func(i int) {
				v, err := s.PushBlob(a, id, 0, nz, ct)
				if err != nil {
					errCount.Add(1)
					t.Errorf("idempotent replay errored: %v", err)
					return
				}
				if v != 1 {
					t.Errorf("replay version = %d, want 1", v)
				}
			})

			if errCount.Load() != 0 {
				t.Fatalf("had %d errors, want 0", errCount.Load())
			}
			_, gotV, err := s.GetBlob(a, id)
			if err != nil {
				t.Fatal(err)
			}
			if gotV != 1 {
				t.Fatalf("final version = %d, want 1 (no double-advance)", gotV)
			}
			if qb := s.QuotaBytes(a); qb != uint64(len(ct)) {
				t.Fatalf("quota = %d, want %d", qb, len(ct))
			}
		})
	}
}

// Many racers advance the head from the SAME prev-hash (genesis, then again from the
// won head) with DISTINCT records: the pointer-CAS admits exactly one each round —
// the head never forks.
func TestConcurrent_AdvanceHead_SingleWinner(t *testing.T) {
	for _, sf := range concurrentStores() {
		t.Run(sf.name, func(t *testing.T) {
			s := sf.mk(t)
			a := acct(0x12)
			var prevZero [HeadIDLen]byte // genesis prev = zero hash

			const n = 48
			race := func(prev [HeadIDLen]byte, tag string) {
				var winners, mismatches atomic.Int64
				fanOut(n, func(i int) {
					rec := []byte(fmt.Sprintf("%s-record-%03d", tag, i))
					_, err := s.AdvanceHead(a, prev, rec)
					switch {
					case err == nil:
						winners.Add(1)
					case errors.Is(err, ErrHeadCASMismatch):
						mismatches.Add(1)
					default:
						t.Errorf("unexpected AdvanceHead error: %v", err)
					}
				})
				if winners.Load() != 1 || mismatches.Load() != n-1 {
					t.Fatalf("%s race: winners=%d mismatches=%d, want 1/%d", tag, winners.Load(), mismatches.Load(), n-1)
				}
			}

			race(prevZero, "genesis")
			_, headID, err := s.GetHead(a)
			if err != nil {
				t.Fatal(err)
			}
			race(headID, "second")
		})
	}
}

// Many racers each PutBlob a DISTINCT blob of fixed size: the dedup byte counter ends
// at the exact sum — the read-modify-write on quotaBytes never loses an add.
func TestConcurrent_QuotaAccounting_DistinctBlobs(t *testing.T) {
	for _, sf := range concurrentStores() {
		t.Run(sf.name, func(t *testing.T) {
			s := sf.mk(t)
			a := acct(0x13)
			const n = 64
			const size = 40
			fanOut(n, func(i int) {
				ct := bytes.Repeat([]byte{byte('a' + i%26)}, size)
				if _, err := s.PutBlob(a, blob(byte(i)), ct); err != nil {
					t.Errorf("put %d: %v", i, err)
				}
			})
			if qb := s.QuotaBytes(a); qb != uint64(n*size) {
				t.Fatalf("quota = %d, want %d (no lost add under concurrency)", qb, n*size)
			}
		})
	}
}

// Concurrent AckCursor of positions 1..n for one device: the cursor is monotone, so
// the final value is the max (n) regardless of arrival order — never a regression.
func TestConcurrent_AckCursor_Monotone(t *testing.T) {
	for _, sf := range concurrentStores() {
		t.Run(sf.name, func(t *testing.T) {
			s := sf.mk(t)
			a, d := acct(0x14), deviceID(0x01)
			const n = 64
			fanOut(n, func(i int) {
				s.AckCursor(a, d, uint64(i+1))
			})
			if got := s.DeviceCursor(a, d); got != n {
				t.Fatalf("final cursor = %d, want %d (monotone max)", got, n)
			}
		})
	}
}

// Concurrent puts across many accounts sharing the same blob-id values: each vault is
// an isolated namespace, so every account ends with exactly its own bytes — no
// cross-vault bleed under contention.
func TestConcurrent_CrossVaultIsolation(t *testing.T) {
	for _, sf := range concurrentStores() {
		t.Run(sf.name, func(t *testing.T) {
			s := sf.mk(t)
			const accounts = 8
			const perAcct = 16
			const size = 32
			fanOut(accounts*perAcct, func(k int) {
				ai := k / perAcct
				bi := k % perAcct
				a := acct(byte(0x80 + ai))
				ct := bytes.Repeat([]byte{byte('a' + bi)}, size)
				if _, err := s.PutBlob(a, blob(byte(bi)), ct); err != nil {
					t.Errorf("put a=%d b=%d: %v", ai, bi, err)
				}
			})
			for ai := 0; ai < accounts; ai++ {
				a := acct(byte(0x80 + ai))
				if qb := s.QuotaBytes(a); qb != uint64(perAcct*size) {
					t.Errorf("account %d quota = %d, want %d (cross-vault bleed)", ai, qb, perAcct*size)
				}
			}
		})
	}
}
