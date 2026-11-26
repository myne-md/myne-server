// SPDX-License-Identifier: AGPL-3.0-only

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

// TestMetricsHook_FedByPush proves the aggregate metric hook (MYND-440) is actually
// invoked by the push path with the stored byte count — the wiring gap where
// `myne_blobs_stored_total` / `_bytes_stored_total` were defined but never fed.
func TestMetricsHook_FedByPush(t *testing.T) {
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

	blobs, bytesN := 0, 0
	mux := http.NewServeMux()
	New(st, ts).WithMetrics(func(n int) { blobs++; bytesN += n }).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	token := hex.EncodeToString(res.Token)

	id := strings.Repeat("aa", 16)
	nonce := strings.Repeat("cb", 24)
	ct := base64.StdEncoding.EncodeToString([]byte("hello-ciphertext")) // 16 bytes
	p := `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonce + `","ciphertext_b64":"` + ct + `"}]}`

	resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push status %d, want 200", resp.StatusCode)
	}
	if blobs != 1 || bytesN != 16 {
		t.Fatalf("metrics hook = (%d blobs, %d bytes), want (1, 16)", blobs, bytesN)
	}
}
