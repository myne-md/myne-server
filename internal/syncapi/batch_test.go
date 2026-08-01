// SPDX-License-Identifier: AGPL-3.0

package syncapi

// handlePush must run EVERY mutation of one request inside ONE store batch
// (myne-server#6). Without it the fs backend rewrote the whole vault index per
// blob — plus once more per attachment association and per tombstone — so a push
// carrying N blobs was quadratic in N and a 50k-blob first sync never returned.
//
// The wiring is what these tests gate: the store-level coalescing is proved in
// internal/store, but a handler that forgot to open the batch, opened two, or left
// a mutation outside one would still pass every test over there.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// batchSpy wraps a BlobStore and records, for every mutation the push path performs,
// whether it ran inside a store batch.
type batchSpy struct {
	store.BlobStore

	mu        sync.Mutex
	depth     int
	batches   int
	mutations int
	outside   int
}

func (s *batchSpy) Batch(a ids.AccountNumberHash, fn func() error) error {
	s.mu.Lock()
	s.batches++
	s.depth++
	s.mu.Unlock()
	err := s.BlobStore.Batch(a, fn)
	s.mu.Lock()
	s.depth--
	s.mu.Unlock()
	return err
}

func (s *batchSpy) note() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutations++
	if s.depth == 0 {
		s.outside++
	}
}

func (s *batchSpy) PushBlob(a ids.AccountNumberHash, id ids.BlobID, base store.Version, nonce [store.ContentNonceLen]byte, ct []byte) (store.Version, error) {
	s.note()
	return s.BlobStore.PushBlob(a, id, base, nonce, ct)
}

func (s *batchSpy) SetBlobAttachmentID(a ids.AccountNumberHash, id ids.BlobID, attachmentIDHex string) error {
	s.note()
	return s.BlobStore.SetBlobAttachmentID(a, id, attachmentIDHex)
}

func (s *batchSpy) SetTombstone(a ids.AccountNumberHash, id ids.BlobID, final store.Version) error {
	s.note()
	return s.BlobStore.SetTombstone(a, id, final)
}

func (s *batchSpy) AdvanceHead(a ids.AccountNumberHash, prev [store.HeadIDLen]byte, rec []byte) ([store.HeadIDLen]byte, error) {
	s.note()
	return s.BlobStore.AdvanceHead(a, prev, rec)
}

// setupWith wires an enrolled device against a caller-supplied store, mirroring
// setup() in syncapi_test.go.
func setupWith(t *testing.T, st store.BlobStore) (*httptest.Server, string) {
	t.Helper()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)
	var a ids.AccountNumberHash
	a[0] = 0x42
	var d ids.DeviceID
	d[0] = 0x01
	res, err := en.Enroll(a, d, auth.PathPassword)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(st, ts).Register(mux)
	return httptest.NewServer(mux), hex.EncodeToString(res.Token)
}

// pushBlobIDHex builds the n-th distinct blob id as hex.
func pushBlobIDHex(n int) string {
	var id ids.BlobID
	id[0] = byte(n >> 8)
	id[1] = byte(n)
	return hex.EncodeToString(id[:])
}

func nonceHex(b byte) string {
	var n [store.ContentNonceLen]byte
	for i := range n {
		n[i] = b
	}
	return hex.EncodeToString(n[:])
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// One push carrying many blobs — including an attachment record and a tombstone,
// the two shapes that each performed a SECOND and THIRD index rewrite of their own
// — plus a head, must open exactly one batch and leave nothing outside it.
func TestPush_AllMutationsRunInOneStoreBatch(t *testing.T) {
	spy := &batchSpy{BlobStore: store.NewMemStore()}
	srv, tok := setupWith(t, spy)
	defer srv.Close()

	const n = 32
	req := pushReq{NewHead: &pushHead{
		PrevHeadHashHex: hex.EncodeToString(make([]byte, store.HeadIDLen)),
		RecordB64:       base64.StdEncoding.EncodeToString([]byte("genesis-head")),
	}}
	for i := 0; i < n; i++ {
		req.Blobs = append(req.Blobs, pushBlob{
			BlobIDHex:     pushBlobIDHex(i),
			BaseVersion:   0,
			ContentNonce:  nonceHex(byte(i)),
			CiphertextB64: base64.StdEncoding.EncodeToString([]byte("ct")),
		})
	}
	// An attachment record: the key is the full id's first 16 bytes (§4.2).
	attID := make([]byte, 32)
	for i := range attID {
		attID[i] = 0xC0
	}
	req.Blobs = append(req.Blobs, pushBlob{
		BlobIDHex:       hex.EncodeToString(attID[:ids.BlobIDLen]),
		BaseVersion:     0,
		ContentNonce:    nonceHex(0xC1),
		CiphertextB64:   "",
		AttachmentIDHex: hex.EncodeToString(attID),
	})
	// A note tombstone.
	req.Blobs = append(req.Blobs, pushBlob{
		BlobIDHex:     pushBlobIDHex(1000),
		BaseVersion:   0,
		ContentNonce:  nonceHex(0xD1),
		CiphertextB64: base64.StdEncoding.EncodeToString([]byte("final")),
		Tombstone:     true,
	})

	resp, body := do(t, srv, http.MethodPost, "/sync/push", tok, mustJSON(t, req))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push: status %d body %s", resp.StatusCode, body)
	}
	var got pushResp
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode push resp: %v", err)
	}
	if len(got.Results) != len(req.Blobs) {
		t.Fatalf("results = %d, want %d", len(got.Results), len(req.Blobs))
	}
	if got.HeadIDHex == "" {
		t.Fatal("head was not advanced")
	}

	spy.mu.Lock()
	defer spy.mu.Unlock()
	if spy.batches != 1 {
		t.Fatalf("store batches opened = %d, want exactly 1 for the request", spy.batches)
	}
	// n blobs + attachment record (push + association) + tombstone (push + record)
	// + head = every mutation the request performs.
	if spy.mutations != n+2+2+1 {
		t.Fatalf("mutations = %d, want %d", spy.mutations, n+2+2+1)
	}
	if spy.outside != 0 {
		t.Fatalf("%d mutations ran outside the batch — each one is a full index rewrite on the fs backend", spy.outside)
	}
}

// A request rejected mid-loop still closes its batch cleanly and keeps the
// pre-conflict prefix stored, exactly as it did when each blob persisted itself.
func TestPush_BlobStaleStillClosesTheBatch(t *testing.T) {
	spy := &batchSpy{BlobStore: store.NewMemStore()}
	srv, tok := setupWith(t, spy)
	defer srv.Close()

	good := pushBlobIDHex(1)
	stale := pushBlobIDHex(2)
	req := pushReq{Blobs: []pushBlob{
		{BlobIDHex: good, BaseVersion: 0, ContentNonce: nonceHex(1), CiphertextB64: base64.StdEncoding.EncodeToString([]byte("a"))},
		{BlobIDHex: stale, BaseVersion: 7, ContentNonce: nonceHex(2), CiphertextB64: base64.StdEncoding.EncodeToString([]byte("b"))},
	}}
	resp, body := do(t, srv, http.MethodPost, "/sync/push", tok, mustJSON(t, req))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", resp.StatusCode, body)
	}
	var eb errBody
	if err := json.Unmarshal(body, &eb); err != nil || eb.ErrorCode != "blob_stale" {
		t.Fatalf("error body = %s (err %v), want blob_stale", body, err)
	}

	spy.mu.Lock()
	defer spy.mu.Unlock()
	if spy.batches != 1 {
		t.Fatalf("store batches opened = %d, want 1", spy.batches)
	}
	if spy.depth != 0 {
		t.Fatalf("batch left open after the conflict (depth %d)", spy.depth)
	}
	if spy.outside != 0 {
		t.Fatalf("%d mutations ran outside the batch", spy.outside)
	}
}

// The end-to-end shape of #6 in miniature: one request carrying many blobs over the
// FS backend lands them all and serves them back. It is the fs backend that had the
// quadratic index write, and no other syncapi test exercises it.
func TestPush_LargeRequestOverFSStore(t *testing.T) {
	st, err := store.NewFSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, tok := setupWith(t, st)
	defer srv.Close()

	const n = 300
	var req pushReq
	for i := 0; i < n; i++ {
		req.Blobs = append(req.Blobs, pushBlob{
			BlobIDHex:     pushBlobIDHex(i),
			BaseVersion:   0,
			ContentNonce:  nonceHex(byte(i)),
			CiphertextB64: base64.StdEncoding.EncodeToString([]byte("ciphertext")),
		})
	}
	resp, body := do(t, srv, http.MethodPost, "/sync/push", tok, mustJSON(t, req))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push: status %d body %s", resp.StatusCode, body)
	}
	var got pushResp
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode push resp: %v", err)
	}
	if len(got.Results) != n {
		t.Fatalf("results = %d, want %d", len(got.Results), n)
	}
	for _, r := range got.Results {
		if r.Version != 1 {
			t.Fatalf("blob %s version = %d, want 1", r.BlobIDHex, r.Version)
		}
	}

	// And a pull sees every one of them.
	resp, body = do(t, srv, http.MethodGet, "/sync/pull?cursor=0&limit=1024", tok, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pull: status %d body %s", resp.StatusCode, body)
	}
	var pr pullResp
	if err := json.Unmarshal(body, &pr); err != nil {
		t.Fatalf("decode pull resp: %v", err)
	}
	if len(pr.Metas) != n {
		t.Fatalf("pull returned %d metas, want %d", len(pr.Metas), n)
	}
}
