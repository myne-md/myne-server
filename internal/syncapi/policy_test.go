// SPDX-License-Identifier: AGPL-3.0

package syncapi

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/gcquota"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

func setupPolicy(t *testing.T, rl RateLimiter, qg QuotaGuard) (*httptest.Server, string, *store.MemStore, ids.AccountNumberHash) {
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
	mux := http.NewServeMux()
	New(st, ts).WithPolicy(rl, qg).Register(mux)
	return httptest.NewServer(mux), hex.EncodeToString(res.Token), st, a
}

func TestPolicy_QuotaExceeded507(t *testing.T) {
	srv, token, _, _ := setupPolicy(t, nil, gcquota.NewQuotaGuard(10))
	defer srv.Close()
	id := strings.Repeat("aa", 16)
	nonce := strings.Repeat("cb", 24)
	big := base64.StdEncoding.EncodeToString(make([]byte, 20)) // > 10 ceiling
	p := `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonce + `","ciphertext_b64":"` + big + `"}]}`
	resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, p)
	if resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("quota push status %d, want 507", resp.StatusCode)
	}
}

func TestPolicy_RateLimited429(t *testing.T) {
	srv, token, _, _ := setupPolicy(t, gcquota.NewRateLimiter(1, 0), nil)
	defer srv.Close()
	if resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", token, ""); resp.StatusCode != 200 {
		t.Fatalf("first pull status %d, want 200", resp.StatusCode)
	}
	if resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", token, ""); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second pull status %d, want 429", resp.StatusCode)
	}
}

func TestPolicy_CursorExpired410(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	// Drive the store to a reclaim floor of 2: two blobs, tombstone the second, reclaim it.
	_, _ = st.PushBlob(a, ids.BlobID{0x01}, 0, [store.ContentNonceLen]byte{}, []byte("a"))
	_, _ = st.PushBlob(a, ids.BlobID{0x02}, 0, [store.ContentNonceLen]byte{}, []byte("b"))
	_ = st.SetTombstone(a, ids.BlobID{0x02}, 1)
	_ = st.ReclaimTombstone(a, ids.BlobID{0x02}) // floor → 2
	if st.GCFloor(a) != 2 {
		t.Fatalf("GCFloor = %d, want 2", st.GCFloor(a))
	}
	// Pull with a cursor below the floor → 410 cursor_expired.
	resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=1", token, "")
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("stale-cursor pull status %d, want 410", resp.StatusCode)
	}
}

// A reconcile-mode pull is the client walking the whole manifest, so a sub-floor
// cursor must be SERVED (not 410'd) — otherwise a vault whose reclaim floor sits
// beyond the first pull page wedges any re-paginating device on page 2 forever.
func TestPolicy_ReconcileBypassesFloor(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	_, _ = st.PushBlob(a, ids.BlobID{0x01}, 0, [store.ContentNonceLen]byte{}, []byte("a"))
	_, _ = st.PushBlob(a, ids.BlobID{0x02}, 0, [store.ContentNonceLen]byte{}, []byte("b"))
	_ = st.SetTombstone(a, ids.BlobID{0x02}, 1)
	_ = st.ReclaimTombstone(a, ids.BlobID{0x02}) // floor → 2
	if st.GCFloor(a) != 2 {
		t.Fatalf("GCFloor = %d, want 2", st.GCFloor(a))
	}
	// Same sub-floor cursor, but reconcile=1 → served, not rejected.
	resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=1&reconcile=1", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reconcile sub-floor pull status %d, want 200", resp.StatusCode)
	}
}
