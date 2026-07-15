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
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

func setupFrozen(t *testing.T, frozen func(ids.AccountNumberHash) bool) (*httptest.Server, string) {
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
	New(st, ts).WithFrozenCheck(frozen).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, hex.EncodeToString(res.Token)
}

func pushBody() string {
	id := strings.Repeat("aa", 16)
	nonce := strings.Repeat("cb", 24)
	ct := base64.StdEncoding.EncodeToString([]byte("x"))
	return `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonce + `","ciphertext_b64":"` + ct + `"}]}`
}

// TestFrozen_BlocksPushNotPull is the "frozen is minimal" invariant: a frozen
// account's PUSH is refused (403), but its PULL is never blocked (MYND-506).
func TestFrozen_BlocksPushNotPull(t *testing.T) {
	srv, token := setupFrozen(t, func(ids.AccountNumberHash) bool { return true })

	if resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", token, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("frozen PULL status %d, want 200 (pull is never blocked)", resp.StatusCode)
	}
	if resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, pushBody()); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("frozen PUSH status %d, want 403", resp.StatusCode)
	}
}

// TestFrozen_UnfrozenAllowsPush: an un-frozen account pushes normally.
func TestFrozen_UnfrozenAllowsPush(t *testing.T) {
	srv, token := setupFrozen(t, func(ids.AccountNumberHash) bool { return false })
	if resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, pushBody()); resp.StatusCode != http.StatusOK {
		t.Fatalf("unfrozen PUSH status %d, want 200", resp.StatusCode)
	}
}
