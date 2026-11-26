// SPDX-License-Identifier: AGPL-3.0-only

package attachments

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
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

// The attachment routes are authed routes, so `server-protocol.md` §3.1's
// `device_revoked` MUST applies to them too (MYND-574 task 94).
//
// The pair is the test. A revoked device must hear `device_revoked` on EVERY
// authed route, not just whichever one it happened to call first — a client whose
// sync route says "you were removed" while its attachment route says "sign in
// again" acts on whichever answer arrived, which is a race. And an unknown token
// must still hear `unauthenticated`, because a web client treats the revoked code
// as terminal and erases its local copy: answering it on a guess is destructive.
func TestAttachment_RevokedDeviceGetsDeviceRevokedCode(t *testing.T) {
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
	srv := httptest.NewServer(mux)
	defer srv.Close()
	token := hex.EncodeToString(res.Token)
	id := strings.Repeat("cd", 32)

	// Still enrolled: the route authenticates, so a 401 here would mean the test
	// is measuring the wrong thing.
	if resp, _ := req(t, srv, http.MethodGet, "/attachments/"+id, token, "", nil); resp.StatusCode == http.StatusUnauthorized {
		t.Fatal("live token rejected before the device was revoked")
	}

	if err := reg.Retire(a, d); err != nil {
		t.Fatal(err)
	}

	codeFor := func(bearer string) (int, string) {
		resp, body := req(t, srv, http.MethodGet, "/attachments/"+id, bearer, "", nil)
		var eb struct {
			ErrorCode string `json:"error_code"`
		}
		_ = json.Unmarshal(body, &eb)
		return resp.StatusCode, eb.ErrorCode
	}

	if status, code := codeFor(token); status != http.StatusUnauthorized || code != "device_revoked" {
		t.Fatalf("revoked device: want 401 device_revoked, got %d %q", status, code)
	}
	if status, code := codeFor("ab" + token[2:]); status != http.StatusUnauthorized || code != "unauthenticated" {
		t.Fatalf("unknown token: want 401 unauthenticated, got %d %q", status, code)
	}
}

// #7: the resume probe is a HEAD, and a HEAD response has no body — Go's
// net/http discards what the handler writes, and the client's codec does not
// read one. So `device_revoked` was written into the one place neither side
// could see, on the one route where the distinction decides whether a client
// erases its local copy.
func TestAttachment_RevokedDeviceCodeIsReadableOnHEAD(t *testing.T) {
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
	srv := httptest.NewServer(mux)
	defer srv.Close()
	token := hex.EncodeToString(res.Token)
	id := strings.Repeat("22", 32)

	if err := reg.Retire(a, d); err != nil {
		t.Fatal(err)
	}

	resp, body := req(t, srv, http.MethodHead, "/attachments/"+id, token, "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
	// The body really is empty on HEAD — that is the whole point.
	if len(body) != 0 {
		t.Fatalf("HEAD must carry no body, got %d bytes", len(body))
	}
	if got := resp.Header.Get("X-Error-Code"); got != "device_revoked" {
		t.Fatalf("want X-Error-Code device_revoked, got %q", got)
	}
}

// #9: uploads precede the push, so a freeze that only gates `/sync/push` let a
// frozen account keep writing attachment bytes — and those are the bytes GC
// cannot reclaim, because no head references them.
func TestAttachment_FrozenAccountCannotUploadButCanStillRead(t *testing.T) {
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
	frozen := false
	mux := http.NewServeMux()
	New(st, ts).WithFrozenCheck(func(ids.AccountNumberHash) bool { return frozen }).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	token := hex.EncodeToString(res.Token)
	id := strings.Repeat("33", 32)

	// Unfrozen: the upload lands, so a later refusal is the freeze and not a
	// broken route.
	body := []byte("ciphertext")
	resp, _ := req(t, srv, http.MethodPut, "/attachments/"+id+"?offset=0&total="+strconv.Itoa(len(body)), token, "", body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("unfrozen upload: want 2xx, got %d", resp.StatusCode)
	}

	frozen = true
	id2 := strings.Repeat("44", 32)
	resp, respBody := req(t, srv, http.MethodPut, "/attachments/"+id2+"?offset=0&total="+strconv.Itoa(len(body)), token, "", body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("frozen upload: want 403, got %d", resp.StatusCode)
	}
	var eb struct {
		ErrorCode string `json:"error_code"`
	}
	_ = json.Unmarshal(respBody, &eb)
	if eb.ErrorCode != "frozen" {
		t.Fatalf("want error_code frozen, got %q", eb.ErrorCode)
	}

	// READS are never gated — freezing must not hold data hostage.
	resp, _ = req(t, srv, http.MethodGet, "/attachments/"+id, token, "", nil)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("frozen read: want 2xx, got %d", resp.StatusCode)
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
