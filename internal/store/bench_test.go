// SPDX-License-Identifier: AGPL-3.0

package store

// Throughput benchmarks for the hot store paths on BOTH backends (in-memory reference
// and on-disk production). They document per-op cost and serve as a regression guard:
// `go test -bench=. -benchmem ./internal/store` compares mem vs fs for push (write),
// get (read), changed-since (pull), and advance-head.

import (
	"bytes"
	"testing"
)

type benchBackend struct {
	name string
	mk   func(b *testing.B) BlobStore
}

func benchBackends() []benchBackend {
	return []benchBackend{
		{"mem", func(b *testing.B) BlobStore { return NewMemStore() }},
		{"fs", func(b *testing.B) BlobStore {
			s, err := NewFSStore(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			return s
		}},
	}
}

func BenchmarkPushBlob(b *testing.B) {
	for _, bk := range benchBackends() {
		b.Run(bk.name, func(b *testing.B) {
			s := bk.mk(b)
			a, id, nz := acct(1), blob(1), nonce(1)
			ct := bytes.Repeat([]byte{0x5a}, 256)
			b.ResetTimer()
			base := Version(0)
			for i := 0; i < b.N; i++ {
				ct[0]++ // vary the body so each push actually advances (not idempotent)
				v, err := s.PushBlob(a, id, base, nz, ct)
				if err != nil {
					b.Fatal(err)
				}
				base = v
			}
		})
	}
}

// BenchmarkPushRequestNBlobs measures a whole REQUEST-shaped push — N distinct new
// blobs into one vault — batched against unbatched. BenchmarkPushBlob above pushes
// the same blob into an otherwise-empty vault, so it never sees the cost that
// myne-server#6 reported: per-mutation index writes rebuild every entry stored so
// far, making the request quadratic in N. This is the benchmark that shows it, and
// the one to re-run when touching the persist path.
func BenchmarkPushRequestNBlobs(b *testing.B) {
	const n = 500
	ct := bytes.Repeat([]byte{0x5a}, 256)
	modes := []struct {
		name    string
		batched bool
	}{{"batched", true}, {"unbatched", false}}

	for _, bk := range benchBackends() {
		for _, mode := range modes {
			b.Run(bk.name+"/"+mode.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					s := bk.mk(b) // a fresh vault per iteration — N is the variable
					a := acct(1)
					b.StartTimer()

					push := func() error {
						for j := 0; j < n; j++ {
							if _, err := s.PushBlob(a, blobN(j), 0, nonce(byte(j)), ct); err != nil {
								return err
							}
						}
						return nil
					}
					var err error
					if mode.batched {
						err = s.Batch(a, push)
					} else {
						err = push()
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkGetBlob(b *testing.B) {
	for _, bk := range benchBackends() {
		b.Run(bk.name, func(b *testing.B) {
			s := bk.mk(b)
			a, id := acct(1), blob(1)
			if _, err := s.PutBlob(a, id, bytes.Repeat([]byte{0x5a}, 256)); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := s.GetBlob(a, id); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkChangedSince(b *testing.B) {
	for _, bk := range benchBackends() {
		b.Run(bk.name, func(b *testing.B) {
			s := bk.mk(b)
			a := acct(1)
			for i := 0; i < 100; i++ { // a populated vault: 100 blobs
				if _, err := s.PutBlob(a, blob(byte(i)), bytes.Repeat([]byte{byte(i)}, 128)); err != nil {
					b.Fatal(err)
				}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if metas, _ := s.ChangedSince(a, 0, 0); len(metas) == 0 {
					b.Fatal("empty page")
				}
			}
		})
	}
}

func BenchmarkAdvanceHead(b *testing.B) {
	for _, bk := range benchBackends() {
		b.Run(bk.name, func(b *testing.B) {
			s := bk.mk(b)
			a := acct(1)
			var prev [HeadIDLen]byte // genesis = zero
			rec := bytes.Repeat([]byte{0x33}, 128)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				next, err := s.AdvanceHead(a, prev, rec)
				if err != nil {
					b.Fatal(err)
				}
				prev = next // chain from the head we just set
			}
		})
	}
}
