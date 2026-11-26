// SPDX-License-Identifier: AGPL-3.0-only

package attachments

import (
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

func setupPolicy(t *testing.T, rl RateLimiter, qg AttachQuota, used func(ids.AccountNumberHash) uint64, maxIDs int) (*httptest.Server, string, ids.AccountNumberHash) {
	t.Helper()
	st := NewStore().WithMaxIDs(maxIDs)
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)
	var a ids.AccountNumberHash
	a[0] = 0x42
	var d ids.DeviceID
	d[0] = 1
	res, err := en.Enroll(a, d, auth.PathPassword)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(st, ts).WithPolicy(rl, qg, used).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, hex.EncodeToString(res.Token), a
}

// A rate-limited attachment PUT returns 429 once the per-account bucket drains.
func TestAttachment_RateLimited429(t *testing.T) {
	srv, token, _ := setupPolicy(t, gcquota.NewRateLimiter(1, 0), nil, nil, 0)
	id := strings.Repeat("ab", 32)
	if resp, _ := req(t, srv, http.MethodPut, "/attachments/"+id+"?offset=0&total=3", token, "", []byte("abc")); resp.StatusCode != http.StatusOK {
		t.Fatalf("first PUT status %d, want 200", resp.StatusCode)
	}
	if resp, _ := req(t, srv, http.MethodPut, "/attachments/"+id+"?offset=3&total=3", token, "", []byte("x")); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second PUT status %d, want 429", resp.StatusCode)
	}
}

// UnifiedCeilingAntiBypass: bytes already stored in the BLOB store count against the
// SAME AS17 ceiling, so an attachment PUT that would cross it is refused (507). This
// is the regression guard for the pre-fix bypass (attachments had a separate budget).
func TestAttachment_UnifiedCeilingAntiBypass(t *testing.T) {
	bst := store.NewMemStore()
	var a ids.AccountNumberHash
	a[0] = 0x42
	if _, err := bst.PushBlob(a, ids.BlobID{0x01}, 0, [store.ContentNonceLen]byte{}, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	qg := gcquota.NewQuotaGuard(10) // ceiling 10 bytes
	used := func(acc ids.AccountNumberHash) uint64 { return bst.QuotaBytes(acc) }
	srv, token, _ := setupPolicy(t, nil, qg, used, 0)
	id := strings.Repeat("cd", 32)
	// 8 (blob) + 5 (attachment total) = 13 > 10 → 507.
	if resp, _ := req(t, srv, http.MethodPut, "/attachments/"+id+"?offset=0&total=5", token, "", []byte("hello")); resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("over-ceiling attachment PUT status %d, want 507", resp.StatusCode)
	}
}

// Under the ceiling the same PUT is accepted (boundary/regression).
func TestAttachment_UnderCeilingAccepted(t *testing.T) {
	qg := gcquota.NewQuotaGuard(10)
	used := func(ids.AccountNumberHash) uint64 { return 0 }
	srv, token, _ := setupPolicy(t, nil, qg, used, 0)
	id := strings.Repeat("ef", 32)
	if resp, _ := req(t, srv, http.MethodPut, "/attachments/"+id+"?offset=0&total=5", token, "", []byte("hello")); resp.StatusCode != http.StatusOK {
		t.Fatalf("under-ceiling PUT status %d, want 200", resp.StatusCode)
	}
}

// The per-vault id cap refuses a NEW attachment id once full (507).
func TestAttachment_IDCapExceeded(t *testing.T) {
	srv, token, _ := setupPolicy(t, nil, nil, nil, 1) // cap = 1 distinct id
	id1 := strings.Repeat("11", 32)
	id2 := strings.Repeat("22", 32)
	if resp, _ := req(t, srv, http.MethodPut, "/attachments/"+id1+"?offset=0&total=3", token, "", []byte("abc")); resp.StatusCode != http.StatusOK {
		t.Fatalf("first id PUT status %d, want 200", resp.StatusCode)
	}
	if resp, _ := req(t, srv, http.MethodPut, "/attachments/"+id2+"?offset=0&total=3", token, "", []byte("abc")); resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("second id PUT status %d, want 507 (id cap)", resp.StatusCode)
	}
}
