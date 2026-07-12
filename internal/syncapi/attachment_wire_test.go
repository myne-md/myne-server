// SPDX-License-Identifier: AGPL-3.0

package syncapi

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// recordedDeleter captures attachmentDeleter invocations (the §11.4 body bridge).
type recordedDeleter struct {
	mu    sync.Mutex
	calls [][32]byte
}

func (r *recordedDeleter) fn(_ ids.AccountNumberHash, id [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, id)
}

func setupWithDeleter(t *testing.T) (*httptest.Server, string, *recordedDeleter) {
	t.Helper()
	st := store.NewMemStore()
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
	del := &recordedDeleter{}
	mux := http.NewServeMux()
	New(st, ts).WithAttachmentDeleter(del.fn).Register(mux)
	return httptest.NewServer(mux), hex.EncodeToString(res.Token), del
}

// An attachment record (MYND-468): 16-byte record key = the 32-byte id's first
// half, EMPTY inline ciphertext, full id on attachment_id_hex; the pull meta
// echoes the full id back.
func TestPush_AttachmentRecordEchoesFullIDOnPull(t *testing.T) {
	srv, token, _ := setupWithDeleter(t)
	defer srv.Close()

	fullID := strings.Repeat("ee", 32)
	prefix := strings.Repeat("ee", 16)
	nonce := strings.Repeat("ab", 24)

	push := `{"blobs":[{"blob_id_hex":"` + prefix + `","base_version":0,"content_nonce_hex":"` + nonce +
		`","ciphertext_b64":"","attachment_id_hex":"` + fullID + `"}]}`
	resp, body := do(t, srv, http.MethodPost, "/sync/push", token, push)
	if resp.StatusCode != 200 {
		t.Fatalf("push status %d: %s", resp.StatusCode, body)
	}

	resp, body = do(t, srv, http.MethodGet, "/sync/pull?cursor=0", token, "")
	if resp.StatusCode != 200 {
		t.Fatalf("pull status %d: %s", resp.StatusCode, body)
	}
	var pr pullResp
	if err := json.Unmarshal(body, &pr); err != nil {
		t.Fatal(err)
	}
	if len(pr.Metas) != 1 {
		t.Fatalf("metas = %+v, want 1 attachment record", pr.Metas)
	}
	if pr.Metas[0].UUIDHex != prefix {
		t.Fatalf("record key = %s, want the 16-byte prefix", pr.Metas[0].UUIDHex)
	}
	if pr.Metas[0].AttachmentIDHex != fullID {
		t.Fatalf("attachment_id_hex echo = %q, want %q", pr.Metas[0].AttachmentIDHex, fullID)
	}
	// A NOTE record carries no echo.
	noteID := strings.Repeat("aa", 16)
	push = `{"blobs":[{"blob_id_hex":"` + noteID + `","base_version":0,"content_nonce_hex":"` + nonce +
		`","ciphertext_b64":"bm90ZQ=="}]}`
	if resp, b := do(t, srv, http.MethodPost, "/sync/push", token, push); resp.StatusCode != 200 {
		t.Fatalf("note push status %d: %s", resp.StatusCode, b)
	}
	_, body = do(t, srv, http.MethodGet, "/sync/pull?cursor=0", token, "")
	var pr2 pullResp
	_ = json.Unmarshal(body, &pr2)
	for _, m := range pr2.Metas {
		if m.UUIDHex == noteID && m.AttachmentIDHex != "" {
			t.Fatalf("note record must not carry attachment_id_hex, got %q", m.AttachmentIDHex)
		}
	}
}

// The record key MUST be the full id's first 16 bytes (§4.2 pin) — a mismatch
// is a 400, and nothing is stored.
func TestPush_AttachmentPrefixMismatchRejected(t *testing.T) {
	srv, token, _ := setupWithDeleter(t)
	defer srv.Close()

	fullID := strings.Repeat("ee", 32)
	wrongPrefix := strings.Repeat("dd", 16)
	nonce := strings.Repeat("ab", 24)

	push := `{"blobs":[{"blob_id_hex":"` + wrongPrefix + `","base_version":0,"content_nonce_hex":"` + nonce +
		`","ciphertext_b64":"","attachment_id_hex":"` + fullID + `"}]}`
	resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, push)
	if resp.StatusCode != 400 {
		t.Fatalf("prefix mismatch status = %d, want 400", resp.StatusCode)
	}
	// A malformed full id likewise rejects.
	push = `{"blobs":[{"blob_id_hex":"` + strings.Repeat("ee", 16) + `","base_version":0,"content_nonce_hex":"` + nonce +
		`","ciphertext_b64":"","attachment_id_hex":"zz"}]}`
	resp, _ = do(t, srv, http.MethodPost, "/sync/push", token, push)
	if resp.StatusCode != 400 {
		t.Fatalf("malformed id status = %d, want 400", resp.StatusCode)
	}
}

// An attachment TOMBSTONE record marks the stored body deleted via the bridge
// (§11.4 step 2) and records the blob-plane tombstone for horizon-GC.
func TestPush_AttachmentTombstoneBridgesToBodyDelete(t *testing.T) {
	srv, token, del := setupWithDeleter(t)
	defer srv.Close()

	fullID := strings.Repeat("ee", 32)
	prefix := strings.Repeat("ee", 16)
	nonceReg := strings.Repeat("ab", 24)
	nonceTomb := strings.Repeat("cd", 24)

	// Register, then tombstone.
	push := `{"blobs":[{"blob_id_hex":"` + prefix + `","base_version":0,"content_nonce_hex":"` + nonceReg +
		`","ciphertext_b64":"","attachment_id_hex":"` + fullID + `"}]}`
	if resp, b := do(t, srv, http.MethodPost, "/sync/push", token, push); resp.StatusCode != 200 {
		t.Fatalf("register status %d: %s", resp.StatusCode, b)
	}
	if len(del.calls) != 0 {
		t.Fatal("registration must not delete the body")
	}
	push = `{"blobs":[{"blob_id_hex":"` + prefix + `","base_version":1,"content_nonce_hex":"` + nonceTomb +
		`","ciphertext_b64":"","tombstone":true,"attachment_id_hex":"` + fullID + `"}]}`
	if resp, b := do(t, srv, http.MethodPost, "/sync/push", token, push); resp.StatusCode != 200 {
		t.Fatalf("tombstone status %d: %s", resp.StatusCode, b)
	}
	del.mu.Lock()
	calls := len(del.calls)
	var got [32]byte
	if calls > 0 {
		got = del.calls[0]
	}
	del.mu.Unlock()
	if calls != 1 || hex.EncodeToString(got[:]) != fullID {
		t.Fatalf("deleter calls = %d (id %x), want exactly the tombstoned id", calls, got)
	}
}
