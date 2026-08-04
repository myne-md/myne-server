// SPDX-License-Identifier: AGPL-3.0

package syncapi

// Fuzz targets for the wire-parse surface. Every field a client controls — the push
// JSON body, the blob/meta/cursor query params — is attacker-controlled bytes. The
// invariant is uniform: malformed input must always produce a clean client-error
// status, NEVER a 5xx or a panic (the fuzzer fails automatically on a panic). Run as
// ordinary tests these replay the seed corpus on every `go test`; run with
// `go test -fuzz=FuzzPushBody -fuzztime=30s` they actively explore.

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// fuzzServer builds the handler + one valid bearer token once (testing.TB serves both
// the *testing.F setup and the inner *testing.T), so a target exercises the post-auth
// parse path without re-enrolling per iteration.
func fuzzServer(tb testing.TB) (*http.ServeMux, string) {
	tb.Helper()
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
		tb.Fatal(err)
	}
	mux := http.NewServeMux()
	New(st, ts).Register(mux)
	return mux, hex.EncodeToString(res.Token)
}

// assertNo5xx drives one request and fails on any 5xx. A panic in the handler is
// caught by the fuzzing engine itself, so this only needs to guard the status.
func assertNo5xx(t *testing.T, mux *http.ServeMux, req *http.Request) {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code >= 500 {
		t.Fatalf("5xx on malformed input: status=%d %s %s", rec.Code, req.Method, req.URL)
	}
}

func FuzzPushBody(f *testing.F) {
	mux, token := fuzzServer(f)
	id := strings.Repeat("aa", 16)
	nonce := strings.Repeat("cb", 24)
	zero := strings.Repeat("00", 32)
	for _, s := range []string{
		``,
		`{}`,
		`{"blobs":[]}`,
		`{"blobs":null}`,
		`{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonce + `","ciphertext_b64":"AAA="}]}`,
		`{"blobs":[{"blob_id_hex":"zz","base_version":18446744073709551615,"content_nonce_hex":"x","ciphertext_b64":"!!!!"}]}`,
		`{"new_head":{"prev_head_hash_hex":"` + zero + `","record_b64":"AAA="}}`,
		`{"blobs":[{"tombstone":true}]}`,
		`[[[[[[[[`,
		`{"blobs":[` + strings.Repeat(`{},`, 100) + `{}]}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		req := httptest.NewRequest(http.MethodPost, "/sync/push", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		assertNo5xx(t, mux, req)
	})
}

func FuzzBlobsBody(f *testing.F) {
	mux, token := fuzzServer(f)
	id := strings.Repeat("aa", 16)
	for _, s := range []string{
		``,
		`{}`,
		`{"blob_ids_hex":[]}`,
		`{"blob_ids_hex":null}`,
		`{"blob_ids_hex":["` + id + `"]}`,
		`{"blob_ids_hex":["zz"]}`,
		`{"blob_ids_hex":[""]}`,
		`{"blob_ids_hex":[` + strings.Repeat(`"`+id+`",`, 99) + `"` + id + `"]}`,
		// Far above MaxBlobFetchIDs: the count cap must refuse before the handler
		// allocates a slice sized by the attacker.
		`{"blob_ids_hex":[` + strings.Repeat(`"`+id+`",`, 99_999) + `"` + id + `"]}`,
		`{"blob_ids_hex":"not-an-array"}`,
		`[[[[[[[[`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		req := httptest.NewRequest(http.MethodPost, "/sync/blobs", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		assertNo5xx(t, mux, req)
	})
}

func FuzzBlobIDParam(f *testing.F) {
	mux, token := fuzzServer(f)
	for _, s := range []string{"", "aa", strings.Repeat("aa", 16), "zz", "00", strings.Repeat("f", 1000), "%zz", "../../etc"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		req := httptest.NewRequest(http.MethodGet, "/sync/blob", nil)
		req.URL.RawQuery = url.Values{"id": {id}}.Encode() // safe-encode the fuzzed value
		req.Header.Set("Authorization", "Bearer "+token)
		assertNo5xx(t, mux, req)
	})
}

func FuzzPullQuery(f *testing.F) {
	mux, token := fuzzServer(f)
	seeds := [][2]string{{"0", ""}, {"", ""}, {"-1", "-1"}, {"abc", "xyz"}, {"99999999999999999999999999", "0"}, {"0", "-2147483648"}}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, cursor, limit string) {
		req := httptest.NewRequest(http.MethodGet, "/sync/pull", nil)
		req.URL.RawQuery = url.Values{"cursor": {cursor}, "limit": {limit}}.Encode()
		req.Header.Set("Authorization", "Bearer "+token)
		assertNo5xx(t, mux, req)
	})
}

// FuzzMetaAccountParam fuzzes the PRE-AUTH GET /vault.meta?account=<hex> — the
// bootstrap surface a brand-new (token-less) device hits.
func FuzzMetaAccountParam(f *testing.F) {
	mux, _ := fuzzServer(f)
	for _, s := range []string{"", "aa", strings.Repeat("ab", 32), "zz", "%", strings.Repeat("f", 5000)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, account string) {
		req := httptest.NewRequest(http.MethodGet, "/vault.meta", nil)
		req.URL.RawQuery = url.Values{"account": {account}}.Encode()
		assertNo5xx(t, mux, req)
	})
}
