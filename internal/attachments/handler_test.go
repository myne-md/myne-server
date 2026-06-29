// SPDX-License-Identifier: AGPL-3.0

package attachments

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
)

func setup(t *testing.T) (*httptest.Server, string, *Store, ids.AccountNumberHash) {
	t.Helper()
	st := NewStore()
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
	New(st, ts).Register(mux)
	return httptest.NewServer(mux), hex.EncodeToString(res.Token), st, a
}

func req(t *testing.T, srv *httptest.Server, method, path, token, rangeHdr string, body []byte) (*http.Response, []byte) {
	t.Helper()
	r, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if rangeHdr != "" {
		r.Header.Set("Range", rangeHdr)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

func TestAttachment_ResumableUploadThenRangeDownload(t *testing.T) {
	srv, token, _, _ := setup(t)
	defer srv.Close()
	id := strings.Repeat("ab", 32) // 32-byte attachment-id
	full := []byte("HELLO-WORLD-OPAQUE-CIPHERTEXT")
	total := len(full)

	// Upload in two chunks (resumable): [0:5) then [5:total).
	if resp, _ := req(t, srv, http.MethodPut, "/attachments/"+id+"?offset=0&total="+strconv.Itoa(total), token, "", full[:5]); resp.StatusCode != 200 {
		t.Fatalf("chunk1 status %d", resp.StatusCode)
	}
	// HEAD reports the resume offset.
	resp, _ := req(t, srv, http.MethodHead, "/attachments/"+id, token, "", nil)
	if resp.Header.Get("X-Uploaded-Length") != "5" {
		t.Fatalf("resume offset = %q, want 5", resp.Header.Get("X-Uploaded-Length"))
	}
	if resp, _ := req(t, srv, http.MethodPut, "/attachments/"+id+"?offset=5&total="+strconv.Itoa(total), token, "", full[5:]); resp.StatusCode != 200 {
		t.Fatalf("chunk2 status %d", resp.StatusCode)
	}
	// Complete → HEAD shows X-Complete (dedup signal).
	resp, _ = req(t, srv, http.MethodHead, "/attachments/"+id, token, "", nil)
	if resp.Header.Get("X-Complete") != "1" {
		t.Fatal("attachment not marked complete")
	}

	// Full GET (200) returns the whole opaque blob.
	resp, body := req(t, srv, http.MethodGet, "/attachments/"+id, token, "", nil)
	if resp.StatusCode != 200 || !bytes.Equal(body, full) {
		t.Fatalf("full GET wrong: %d %q", resp.StatusCode, body)
	}
	// Range GET (206) returns the requested slice + Content-Range.
	resp, body = req(t, srv, http.MethodGet, "/attachments/"+id, token, "bytes=0-4", nil)
	if resp.StatusCode != http.StatusPartialContent || !bytes.Equal(body, full[:5]) {
		t.Fatalf("range GET wrong: %d %q", resp.StatusCode, body)
	}
	if cr := resp.Header.Get("Content-Range"); cr != "bytes 0-4/"+strconv.Itoa(total) {
		t.Fatalf("Content-Range = %q", cr)
	}
}

func TestAttachment_BadOffsetConflict(t *testing.T) {
	srv, token, _, _ := setup(t)
	defer srv.Close()
	id := strings.Repeat("cd", 32)
	// Upload at a non-zero offset for a fresh blob → 409 (client re-probes via HEAD).
	if resp, _ := req(t, srv, http.MethodPut, "/attachments/"+id+"?offset=10&total=20", token, "", []byte("x")); resp.StatusCode != http.StatusConflict {
		t.Fatalf("bad-offset status %d, want 409", resp.StatusCode)
	}
}

func TestAttachment_Unauthenticated(t *testing.T) {
	srv, _, _, _ := setup(t)
	defer srv.Close()
	id := strings.Repeat("ef", 32)
	if resp, _ := req(t, srv, http.MethodGet, "/attachments/"+id, "", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth GET status %d, want 401", resp.StatusCode)
	}
}

func TestAttachment_Dedup(t *testing.T) {
	srv, token, st, a := setup(t)
	defer srv.Close()
	id := strings.Repeat("11", 32)
	full := []byte("dup")
	if resp, _ := req(t, srv, http.MethodPut, "/attachments/"+id+"?offset=0&total=3", token, "", full); resp.StatusCode != 200 {
		t.Fatal("upload failed")
	}
	var aid AttachmentID
	b, _ := hex.DecodeString(id)
	copy(aid[:], b)
	if !st.Has(a, aid) {
		t.Fatal("dedup: Has should report the complete attachment")
	}
}
