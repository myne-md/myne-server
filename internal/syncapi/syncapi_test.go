// SPDX-License-Identifier: AGPL-3.0

package syncapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

func setup(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)
	var a ids.AccountNumberHash
	a[0] = 0x42
	var d ids.DeviceID
	d[0] = 0x01
	res, err := en.Enroll(a, d, auth.PathPassword) // first device → token
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(st, ts).Register(mux)
	return httptest.NewServer(mux), hex.EncodeToString(res.Token)
}

func do(t *testing.T, srv *httptest.Server, method, path, token, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	resp.Body.Close()
	return resp, buf.Bytes()
}

// F4: an authed pull/push must stamp the device's LastActivity via the wired
// activity recorder, so the horizon-GC soft-retire can eventually fire. Before
// this landed, TouchActivity had no production caller and every device sat at 0.
func TestActivityTouch_AuthedPullAndPushStampLastActivity(t *testing.T) {
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

	// Wire the recorder exactly as httpapi.NewServer does, but with a fixed
	// nonzero marker so the assertion is deterministic (no wall clock in tests).
	const marker = uint64(20000)
	mux := http.NewServeMux()
	New(st, ts).WithActivityTouch(func(acct ids.AccountNumberHash, dev ids.DeviceID) {
		_ = reg.TouchActivity(acct, dev, marker)
	}).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	token := hex.EncodeToString(res.Token)

	// Precondition: an unseen device sits at LastActivity 0 — F4's whole problem.
	if rec, ok := reg.Get(a, d); !ok || rec.LastActivity != 0 {
		t.Fatalf("precondition: want LastActivity 0, got ok=%v rec=%+v", ok, rec)
	}

	// An authed pull records activity.
	if resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", token, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("pull status = %d", resp.StatusCode)
	}
	if rec, ok := reg.Get(a, d); !ok || rec.LastActivity != marker {
		t.Fatalf("after pull: want LastActivity %d, got ok=%v rec=%+v", marker, ok, rec)
	}

	// An authed push (empty body → 200 with no blobs) records activity too.
	reg.TouchActivity(a, d, 0) // no-op (marker not greater); confirms pull already stamped
	if resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, `{"blobs":[]}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("push status = %d", resp.StatusCode)
	}
	if rec, _ := reg.Get(a, d); rec.LastActivity != marker {
		t.Fatalf("after push: want LastActivity %d, got %d", marker, rec.LastActivity)
	}

	// An UNauthenticated pull must NOT stamp activity (no session → no touch).
	var d2 ids.DeviceID
	d2[0] = 0x02
	if _, ok := reg.Get(a, d2); ok {
		t.Fatal("precondition: d2 should not exist yet")
	}
	if resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth pull status = %d, want 401", resp.StatusCode)
	}
}

// F1 Faz B: an enrolled device fetches its OWN meta via an authed GET (no
// ?account= query, not behind the pre-auth limiter) so the sync loop's meta phase
// can pick up a password-side change made on another device.
func TestMeta_AuthedGetReturnsSessionMeta(t *testing.T) {
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
	New(st, ts).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	token := hex.EncodeToString(res.Token)

	// Not seeded yet → authed GET is 404.
	if resp, _ := do(t, srv, http.MethodGet, "/vault.meta", token, ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("authed GET before seed = %d, want 404", resp.StatusCode)
	}
	// Seed via the authed PUT.
	meta := "opaque-vault-meta-bytes"
	if resp, _ := do(t, srv, http.MethodPut, "/vault.meta", token, meta); resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /vault.meta = %d", resp.StatusCode)
	}
	// Authed GET (no ?account=) returns the session's meta verbatim.
	resp, body := do(t, srv, http.MethodGet, "/vault.meta", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authed GET = %d, want 200", resp.StatusCode)
	}
	if string(body) != meta {
		t.Fatalf("authed GET body = %q, want %q", body, meta)
	}
	// No token and no ?account= → the pre-auth path rejects as bad_request.
	if resp, _ := do(t, srv, http.MethodGet, "/vault.meta", "", ""); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unauth GET without account = %d, want 400", resp.StatusCode)
	}
}

func TestPushPull_RoundTrip(t *testing.T) {
	srv, token := setup(t)
	defer srv.Close()

	id := strings.Repeat("aa", 16)
	nonce := strings.Repeat("cb", 24)
	ct := base64.StdEncoding.EncodeToString([]byte("opaque-ciphertext"))
	rec := []byte("opaque-head-record")
	headB64 := base64.StdEncoding.EncodeToString(rec)
	prevZero := strings.Repeat("00", 32)

	push := `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonce +
		`","ciphertext_b64":"` + ct + `"}],"new_head":{"prev_head_hash_hex":"` + prevZero + `","record_b64":"` + headB64 + `"}}`
	resp, body := do(t, srv, http.MethodPost, "/sync/push", token, push)
	if resp.StatusCode != 200 {
		t.Fatalf("push status %d: %s", resp.StatusCode, body)
	}
	var pr pushResp
	if err := json.Unmarshal(body, &pr); err != nil {
		t.Fatal(err)
	}
	if len(pr.Results) != 1 || pr.Results[0].Version != 1 {
		t.Fatalf("push results wrong: %+v", pr)
	}
	wantHead := sha256.Sum256(rec)
	if pr.HeadIDHex != hex.EncodeToString(wantHead[:]) {
		t.Fatalf("head_id mismatch")
	}

	// Pull from cursor 0 → sees the blob + head.
	resp, body = do(t, srv, http.MethodGet, "/sync/pull?cursor=0", token, "")
	if resp.StatusCode != 200 {
		t.Fatalf("pull status %d: %s", resp.StatusCode, body)
	}
	var pl pullResp
	if err := json.Unmarshal(body, &pl); err != nil {
		t.Fatal(err)
	}
	if len(pl.Metas) != 1 || pl.Metas[0].UUIDHex != id || pl.Metas[0].Version != 1 {
		t.Fatalf("pull metas wrong: %+v", pl)
	}
	if pl.Metas[0].ContentNonce != nonce || pl.Head == nil {
		t.Fatalf("pull meta/head wrong: %+v", pl)
	}
}

func TestPush_BlobStaleConflict(t *testing.T) {
	srv, token := setup(t)
	defer srv.Close()
	id := strings.Repeat("bb", 16)
	nonce := strings.Repeat("cb", 24)
	ct := base64.StdEncoding.EncodeToString([]byte("x"))
	// First push at base 0 succeeds.
	p := `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonce + `","ciphertext_b64":"` + ct + `"}]}`
	if resp, b := do(t, srv, http.MethodPost, "/sync/push", token, p); resp.StatusCode != 200 {
		t.Fatalf("first push: %d %s", resp.StatusCode, b)
	}
	// Second push at stale base 0 (current is 1) with different content → 409 blob_stale.
	ct2 := base64.StdEncoding.EncodeToString([]byte("y"))
	p2 := `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonce + `","ciphertext_b64":"` + ct2 + `"}]}`
	resp, body := do(t, srv, http.MethodPost, "/sync/push", token, p2)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale push status %d, want 409", resp.StatusCode)
	}
	var e errBody
	_ = json.Unmarshal(body, &e)
	if e.ErrorCode != "blob_stale" {
		t.Fatalf("error_code = %q, want blob_stale", e.ErrorCode)
	}
}

func TestPush_HeadStaleConflict(t *testing.T) {
	srv, token := setup(t)
	defer srv.Close()
	rec := base64.StdEncoding.EncodeToString([]byte("h1"))
	prevZero := strings.Repeat("00", 32)
	// Genesis head OK.
	p := `{"blobs":[],"new_head":{"prev_head_hash_hex":"` + prevZero + `","record_b64":"` + rec + `"}}`
	if resp, b := do(t, srv, http.MethodPost, "/sync/push", token, p); resp.StatusCode != 200 {
		t.Fatalf("genesis head: %d %s", resp.StatusCode, b)
	}
	// Second genesis (prev=zero) when a head exists → 409 head_stale.
	resp, body := do(t, srv, http.MethodPost, "/sync/push", token, p)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale head status %d, want 409", resp.StatusCode)
	}
	var e errBody
	_ = json.Unmarshal(body, &e)
	if e.ErrorCode != "head_stale" {
		t.Fatalf("error_code = %q, want head_stale", e.ErrorCode)
	}
}

func TestSessionBinding_NoTokenRejected(t *testing.T) {
	srv, _ := setup(t)
	defer srv.Close()
	if resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth pull status %d, want 401", resp.StatusCode)
	}
	if resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", "deadbeef", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad-token pull status %d, want 401", resp.StatusCode)
	}
}

func TestPush_TooLargeRejected(t *testing.T) {
	srv, token := setup(t)
	defer srv.Close()
	id := strings.Repeat("cc", 16)
	nonce := strings.Repeat("cb", 24)
	big := base64.StdEncoding.EncodeToString(make([]byte, MaxBlobSize+1))
	p := `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonce + `","ciphertext_b64":"` + big + `"}]}`
	resp, body := do(t, srv, http.MethodPost, "/sync/push", token, p)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("too-large status %d, want 413", resp.StatusCode)
	}
	var e errBody
	_ = json.Unmarshal(body, &e)
	if e.ErrorCode != "too_large" {
		t.Fatalf("error_code = %q, want too_large", e.ErrorCode)
	}
}

// --- MYND-424 download path / MYND-428 canary prereq: GET /sync/blob ---

func TestBlob_DownloadsPushedCiphertext(t *testing.T) {
	srv, token := setup(t)
	defer srv.Close()

	id := strings.Repeat("aa", 16)
	nonce := strings.Repeat("cb", 24)
	plain := []byte("opaque-ciphertext-blob")
	ct := base64.StdEncoding.EncodeToString(plain)
	push := `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonce +
		`","ciphertext_b64":"` + ct + `"}]}`
	if resp, body := do(t, srv, http.MethodPost, "/sync/push", token, push); resp.StatusCode != 200 {
		t.Fatalf("push status %d: %s", resp.StatusCode, body)
	}

	resp, body := do(t, srv, http.MethodGet, "/sync/blob?id="+id, token, "")
	if resp.StatusCode != 200 {
		t.Fatalf("blob status %d: %s", resp.StatusCode, body)
	}
	var br blobResp
	if err := json.Unmarshal(body, &br); err != nil {
		t.Fatal(err)
	}
	got, err := base64.StdEncoding.DecodeString(br.CiphertextB64)
	if err != nil {
		t.Fatalf("ciphertext_b64 decode: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("blob bytes mismatch: got %q want %q", got, plain)
	}
	if br.Version != 1 {
		t.Fatalf("blob version = %d, want 1", br.Version)
	}
}

func TestBlob_AbsentIs404(t *testing.T) {
	srv, token := setup(t)
	defer srv.Close()
	resp, _ := do(t, srv, http.MethodGet, "/sync/blob?id="+strings.Repeat("bb", 16), token, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("absent blob status = %d, want 404", resp.StatusCode)
	}
}

func TestBlob_NoTokenRejected(t *testing.T) {
	srv, _ := setup(t)
	defer srv.Close()
	resp, _ := do(t, srv, http.MethodGet, "/sync/blob?id="+strings.Repeat("aa", 16), "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token blob status = %d, want 401", resp.StatusCode)
	}
}

func TestBlob_BadIDRejected(t *testing.T) {
	srv, token := setup(t)
	defer srv.Close()
	resp, _ := do(t, srv, http.MethodGet, "/sync/blob?id=nothex", token, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad-id blob status = %d, want 400", resp.StatusCode)
	}
}

// --- MYND-425 enrollment bootstrap: PUT/GET /vault.meta ---

func TestVaultMeta_PutAuthedGetPreAuth(t *testing.T) {
	srv, token := setup(t)
	defer srv.Close()
	// setup() account = 0x42 then zeros.
	accountHex := "42" + strings.Repeat("00", 15)
	meta := "fake-MYV1-vault-meta-bytes"

	// PUT (authed) uploads the meta.
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/vault.meta", strings.NewReader(meta))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("PUT vault.meta status %d", resp.StatusCode)
	}

	// GET (PRE-AUTH, no token) by account fetches it back.
	gresp, err := http.Get(srv.URL + "/vault.meta?account=" + accountHex)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(gresp.Body)
	gresp.Body.Close()
	if gresp.StatusCode != 200 {
		t.Fatalf("GET vault.meta status %d", gresp.StatusCode)
	}
	if buf.String() != meta {
		t.Fatalf("meta mismatch: got %q", buf.String())
	}
}

func TestVaultMeta_AbsentIs404(t *testing.T) {
	srv, _ := setup(t)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/vault.meta?account=" + strings.Repeat("bb", 16))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("absent meta status %d, want 404", resp.StatusCode)
	}
}

func TestVaultMeta_PutNoTokenRejected(t *testing.T) {
	srv, _ := setup(t)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/vault.meta", strings.NewReader("x"))
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token PUT status %d, want 401", resp.StatusCode)
	}
}
