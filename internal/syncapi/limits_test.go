// SPDX-License-Identifier: AGPL-3.0-only

package syncapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// A push carrying an opaque head record larger than MaxHeadRecordSize is rejected
// with 413 — the record is stored uncounted against quota and re-sent on every
// pull, so an unbounded head is a storage + bandwidth abuse vector.
func TestPush_HeadRecordTooLarge413(t *testing.T) {
	srv, token, _, _ := setupPolicy(t, nil, nil)
	defer srv.Close()
	prev := strings.Repeat("00", store.HeadIDLen) // genesis: expect no current head
	rec := base64.StdEncoding.EncodeToString(make([]byte, MaxHeadRecordSize+1))
	body := `{"new_head":{"prev_head_hash_hex":"` + prev + `","record_b64":"` + rec + `"}}`
	resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize head status %d, want 413", resp.StatusCode)
	}
}

// A head record at exactly the cap is still accepted (boundary).
func TestPush_HeadRecordAtCapAccepted(t *testing.T) {
	srv, token, _, _ := setupPolicy(t, nil, nil)
	defer srv.Close()
	prev := strings.Repeat("00", store.HeadIDLen)
	rec := base64.StdEncoding.EncodeToString(make([]byte, MaxHeadRecordSize))
	body := `{"new_head":{"prev_head_hash_hex":"` + prev + `","record_b64":"` + rec + `"}}`
	resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("at-cap head status %d, want 200", resp.StatusCode)
	}
}

// A client-supplied pull limit above MaxPullLimit is clamped: one page never
// returns more than MaxPullLimit metas regardless of the requested value.
func TestPull_LimitClamped(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	for i := 0; i < MaxPullLimit+50; i++ {
		var id ids.BlobID
		id[0] = byte(i)
		id[1] = byte(i >> 8)
		if _, err := st.PushBlob(a, id, 0, [store.ContentNonceLen]byte{}, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	resp, buf := do(t, srv, http.MethodGet, "/sync/pull?cursor=0&limit=1000000", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pull status %d, want 200", resp.StatusCode)
	}
	var pr pullResp
	if err := json.Unmarshal(buf, &pr); err != nil {
		t.Fatal(err)
	}
	if len(pr.Metas) != MaxPullLimit {
		t.Fatalf("pull returned %d metas, want exactly %d (clamped)", len(pr.Metas), MaxPullLimit)
	}
}
