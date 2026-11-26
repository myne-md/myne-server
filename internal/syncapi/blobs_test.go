// SPDX-License-Identifier: AGPL-3.0-only

package syncapi

// POST /sync/blobs — the batch read path (myne-md/myne#240). These tests are the
// batch twin of TestBlob_Reclaimed410_Missing404_Live200: the single-blob route
// signals a reclaimed record with a fail-closed 410 rather than an empty 200,
// and a route that answers many ids at once has a NEW way to violate that same
// rule — an entry with empty bytes, or an id silently dropped from both arrays.
// Both are pinned here.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/gcquota"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// fetchBody builds a POST /sync/blobs request body from blob ids.
func fetchBody(idHexes ...string) string {
	q := make([]string, len(idHexes))
	for i, h := range idHexes {
		q[i] = `"` + h + `"`
	}
	return `{"blob_ids_hex":[` + strings.Join(q, ",") + `]}`
}

func idHex(id ids.BlobID) string { return hex.EncodeToString(id[:]) }

// decodeBlobs parses a 200 batch response, failing the test on anything else.
func decodeBlobs(t *testing.T, resp *http.Response, body []byte) blobsResp {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("batch fetch status %d, want 200 (body %s)", resp.StatusCode, body)
	}
	var br blobsResp
	if err := json.Unmarshal(body, &br); err != nil {
		t.Fatalf("batch response is not JSON: %v (%s)", err, body)
	}
	return br
}

func (b blobsResp) served(idHexStr string) ([]byte, bool) {
	for _, e := range b.Blobs {
		if e.BlobIDHex == idHexStr {
			ct, err := base64.StdEncoding.DecodeString(e.CiphertextB64)
			if err != nil {
				return nil, false
			}
			return ct, true
		}
	}
	return nil, false
}

func (b blobsResp) omittedCode(idHexStr string) (string, bool) {
	for _, o := range b.Omitted {
		if o.BlobIDHex == idHexStr {
			return o.ErrorCode, true
		}
	}
	return "", false
}

// The three single-route outcomes, all in ONE batch: live serves its bytes,
// reclaimed and absent come back as per-id omissions with the same error codes
// the single route emits as statuses. Arrays disjoint, union == request set.
func TestBlobs_LiveReclaimedMissingInOneBatch(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	seedBlobs(t, st, a, 2)

	live, victim := seededID(1), seededID(2)
	if err := st.SetTombstone(a, victim, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.ReclaimTombstone(a, victim); err != nil {
		t.Fatal(err)
	}
	var missing ids.BlobID
	missing[0] = 0xFF

	resp, body := do(t, srv, http.MethodPost, "/sync/blobs", token,
		fetchBody(idHex(live), idHex(victim), idHex(missing)))
	br := decodeBlobs(t, resp, body)

	ct, ok := br.served(idHex(live))
	if !ok || !bytes.Equal(ct, []byte{1}) {
		t.Fatalf("live blob: served=%v bytes=%v, want the seeded bytes", ok, ct)
	}
	if code, ok := br.omittedCode(idHex(victim)); !ok || code != "blob_reclaimed" {
		t.Fatalf("reclaimed id: omitted=%v code=%q, want blob_reclaimed", ok, code)
	}
	if code, ok := br.omittedCode(idHex(missing)); !ok || code != "not_found" {
		t.Fatalf("absent id: omitted=%v code=%q, want not_found", ok, code)
	}
	// Disjoint, and the union accounts for every requested id exactly once.
	if len(br.Blobs) != 1 || len(br.Omitted) != 2 {
		t.Fatalf("accounting: %d served + %d omitted, want 1 + 2", len(br.Blobs), len(br.Omitted))
	}
	for _, o := range br.Omitted {
		if _, dup := br.served(o.BlobIDHex); dup {
			t.Fatalf("id %s appears in BOTH arrays", o.BlobIDHex)
		}
	}
}

// The fail-closed half, stated on its own so it cannot be deleted along with the
// shape test above. A reclaimed record must be ABSENT from the payload, never an
// entry carrying "" — a blind client cannot tell empty bytes from ciphertext and
// would write 0 bytes over a live note (§11.3, the reason 410 exists).
func TestBlobs_ReclaimedIsNeverAZeroByteEntry(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	seedBlobs(t, st, a, 1)
	victim := seededID(1)
	if err := st.SetTombstone(a, victim, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.ReclaimTombstone(a, victim); err != nil {
		t.Fatal(err)
	}

	resp, body := do(t, srv, http.MethodPost, "/sync/blobs", token, fetchBody(idHex(victim)))
	br := decodeBlobs(t, resp, body)
	if _, ok := br.served(idHex(victim)); ok {
		t.Fatal("a reclaimed id was served as a payload entry")
	}
	for _, e := range br.Blobs {
		if e.CiphertextB64 == "" {
			t.Fatalf("empty ciphertext_b64 in the payload for %s", e.BlobIDHex)
		}
	}
}

// A batch is a new cross-account leak surface: one request now names many ids,
// so a handler that resolved them anywhere but the session's own namespace would
// leak in bulk. B's id must come back not_found — NOT blob_reclaimed, which
// would confirm the id exists somewhere.
func TestBlobs_CrossAccountIDsAreOmittedNotLeaked(t *testing.T) {
	srv, tokenA, tokenB, _, _ := setupTwoAccounts(t)
	defer srv.Close()

	sharedID := strings.Repeat("cc", 16)
	ownID := strings.Repeat("a1", 16)
	nonceHex := strings.Repeat("dd", 24)
	secretB := []byte("account-B-secret-opaque-ciphertext")
	ctB := base64.StdEncoding.EncodeToString(secretB)
	ctA := base64.StdEncoding.EncodeToString([]byte("account-A-own-bytes"))

	push := func(token, id, ct string) {
		t.Helper()
		body := `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonceHex + `","ciphertext_b64":"` + ct + `"}]}`
		if resp, b := do(t, srv, http.MethodPost, "/sync/push", token, body); resp.StatusCode != 200 {
			t.Fatalf("push: %d %s", resp.StatusCode, b)
		}
	}
	push(tokenB, sharedID, ctB)
	push(tokenA, ownID, ctA)

	resp, body := do(t, srv, http.MethodPost, "/sync/blobs", tokenA, fetchBody(ownID, sharedID))
	br := decodeBlobs(t, resp, body)
	if _, ok := br.served(ownID); !ok {
		t.Fatal("A's own blob was not served")
	}
	if code, ok := br.omittedCode(sharedID); !ok || code != "not_found" {
		t.Fatalf("B's id under A's token: omitted=%v code=%q, want not_found", ok, code)
	}
	if bytes.Contains(body, secretB) || strings.Contains(string(body), ctB) {
		t.Fatal("B's ciphertext leaked to A via /sync/blobs")
	}
	// The omission was namespacing, not a broken id: B's own token still reads it.
	rB, bB := do(t, srv, http.MethodPost, "/sync/blobs", tokenB, fetchBody(sharedID))
	if _, ok := decodeBlobs(t, rB, bB).served(sharedID); !ok {
		t.Fatal("B cannot read its own blob — the omission was not namespacing")
	}
}

// Deliberately the OPPOSITE of TestPull_LimitClamped's clamp. A clamped pull page
// still advances a cursor, so the client makes progress and comes back; a
// silently truncated fetch would let a client believe it asked about ids it never
// heard back on. The client knows its own id count exactly, so this is a client
// bug and 413 says so.
func TestBlobs_IDCountAboveMaxIsRejected(t *testing.T) {
	srv, token, _, _ := setupPolicy(t, nil, nil)
	defer srv.Close()

	over := make([]string, MaxBlobFetchIDs+1)
	for i := range over {
		var id ids.BlobID
		id[0] = byte(i >> 8)
		id[1] = byte(i)
		over[i] = idHex(id)
	}
	resp, body := do(t, srv, http.MethodPost, "/sync/blobs", token, fetchBody(over...))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap id count: status %d, want 413 (body %s)", resp.StatusCode, body)
	}
	var eb errBody
	if err := json.Unmarshal(body, &eb); err != nil || eb.ErrorCode != "too_large" {
		t.Fatalf("over-cap error_code %q (err=%v), want too_large", eb.ErrorCode, err)
	}
	// Exactly at the cap is fine.
	okResp, okBody := do(t, srv, http.MethodPost, "/sync/blobs", token, fetchBody(over[:MaxBlobFetchIDs]...))
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("exactly MaxBlobFetchIDs: status %d, want 200 (body %s)", okResp.StatusCode, okBody)
	}
}

// The byte budget truncates instead of refusing, because the client cannot always
// plan correctly (the `size` it windows on is server-advertised and untrusted, and
// an older server omits it). The response describes a clean PREFIX; the ids past
// the cut are simply absent and the client asks again.
func TestBlobs_ByteBudgetServesAPrefix(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()

	const chunk = 3 * 1024 * 1024 // 3 of these overrun the 8 MiB budget
	const n = 4
	all := make([]string, n)
	for i := 1; i <= n; i++ {
		id := seededID(i)
		if _, err := st.PushBlob(a, id, 0, [store.ContentNonceLen]byte{}, make([]byte, chunk)); err != nil {
			t.Fatal(err)
		}
		all[i-1] = idHex(id)
	}

	resp, body := do(t, srv, http.MethodPost, "/sync/blobs", token, fetchBody(all...))
	br := decodeBlobs(t, resp, body)
	if len(br.Blobs) == 0 {
		t.Fatal("the byte budget served nothing — the client can never make progress")
	}
	if len(br.Blobs) >= n {
		t.Fatalf("served %d of %d — the byte budget did not bind", len(br.Blobs), n)
	}
	// A clean prefix: the served ids are the FIRST ones, in request order, and
	// nothing past the cut was appended to either array.
	for i, e := range br.Blobs {
		if e.BlobIDHex != all[i] {
			t.Fatalf("entry %d is %s, want %s — the response is not a request-order prefix", i, e.BlobIDHex, all[i])
		}
	}
	if len(br.Omitted) != 0 {
		t.Fatalf("ids past the byte cut were appended as omissions: %+v", br.Omitted)
	}
}

// A lone blob over the whole budget still travels, or the client loops on it
// forever: the window can never shrink below one. Mirrors push_chunks' rule that
// an oversized lone blob is sent rather than split.
func TestBlobs_OversizedLoneBlobIsServedAlone(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	id := seededID(1)
	if _, err := st.PushBlob(a, id, 0, [store.ContentNonceLen]byte{}, make([]byte, MaxBlobFetchBytes+1)); err != nil {
		t.Fatal(err)
	}
	resp, body := do(t, srv, http.MethodPost, "/sync/blobs", token, fetchBody(idHex(id)))
	br := decodeBlobs(t, resp, body)
	if ct, ok := br.served(idHex(id)); !ok || len(ct) != MaxBlobFetchBytes+1 {
		t.Fatalf("oversized lone blob: served=%v len=%d, want the whole blob", ok, len(ct))
	}
}

// unreadableStore makes GetBlob fail with a non-sentinel error for one id, which
// is what the FSStore empty-body fix now produces and MemStore cannot.
type unreadableStore struct {
	store.BlobStore
	bad ids.BlobID
}

func (s *unreadableStore) GetBlob(a ids.AccountNumberHash, id ids.BlobID) ([]byte, store.Version, error) {
	if id == s.bad {
		return nil, 0, store.ErrBodyUnreadable
	}
	return s.BlobStore.GetBlob(a, id)
}

// An unreadable body is a per-id omission, NOT a 500. A 500 poisons the whole
// window, which kills the client's cycle, which means one bad file wedges that
// account's sync permanently. As an omission the client skips the record without
// adopting a baseline, so the next cycle re-lists it and it self-heals.
func TestBlobs_UnreadableBodyIsOmittedNotA500(t *testing.T) {
	base := store.NewMemStore()
	bad, good := seededID(1), seededID(2)
	st := &unreadableStore{BlobStore: base, bad: bad}
	srv, token := setupWith(t, st)
	defer srv.Close()

	var a ids.AccountNumberHash
	a[0] = 0x42
	for _, id := range []ids.BlobID{bad, good} {
		if _, err := base.PushBlob(a, id, 0, [store.ContentNonceLen]byte{}, []byte("bytes")); err != nil {
			t.Fatal(err)
		}
	}
	resp, body := do(t, srv, http.MethodPost, "/sync/blobs", token, fetchBody(idHex(bad), idHex(good)))
	br := decodeBlobs(t, resp, body)
	if code, ok := br.omittedCode(idHex(bad)); !ok || code != "internal" {
		t.Fatalf("unreadable body: omitted=%v code=%q, want internal", ok, code)
	}
	if _, ok := br.served(idHex(good)); !ok {
		t.Fatal("one unreadable body poisoned the rest of the window")
	}
	if _, ok := br.served(idHex(bad)); ok {
		t.Fatal("an unreadable body was served as a payload entry")
	}
}

// A batch costs ceil(ids/BlobFetchIDsPerToken), so batching buys round-trips
// rather than budget. The one-id case must still cost exactly one, or the
// single-blob fallback path would be penalized for a server that lacks the route.
func TestBlobs_ChargesCeilNPerToken(t *testing.T) {
	srv, token, st, a := setupPolicy(t, gcquota.NewRateLimiter(10, 0), nil)
	defer srv.Close()
	seedBlobs(t, st, a, 1)
	one := idHex(seededID(1))

	// 2 × BlobFetchIDsPerToken + 1 ids → 3 tokens. Repeat ids are fine: the cost
	// is a function of the id COUNT, which is what the server does work for.
	many := make([]string, 2*BlobFetchIDsPerToken+1)
	for i := range many {
		many[i] = one
	}
	if resp, b := do(t, srv, http.MethodPost, "/sync/blobs", token, fetchBody(many...)); resp.StatusCode != 200 {
		t.Fatalf("first batch: %d %s", resp.StatusCode, b)
	}
	// 10 - 3 = 7 left. Six one-id batches cost 1 each; the seventh must 429.
	for i := 0; i < 7; i++ {
		resp, b := do(t, srv, http.MethodPost, "/sync/blobs", token, fetchBody(one))
		if resp.StatusCode != 200 {
			t.Fatalf("one-id batch %d cost more than a token: %d %s", i, resp.StatusCode, b)
		}
	}
	resp, _ := do(t, srv, http.MethodPost, "/sync/blobs", token, fetchBody(one))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("bucket should be spent: status %d, want 429", resp.StatusCode)
	}
}

// Reads are never refused for a frozen account — "frozen is minimal". handleBlob
// and handlePull both omit the freeze gate and the batch route must match them,
// not handlePush. A copy-paste from the push handler is the way this regresses.
func TestBlobs_FrozenAccountStillReads(t *testing.T) {
	srv, token := setupFrozen(t, func(ids.AccountNumberHash) bool { return true })
	// An id the account does not hold is enough: the discriminating status is
	// 403 (the freeze gate fired) vs 200 (it is absent, as it must be).
	resp, body := do(t, srv, http.MethodPost, "/sync/blobs", token, fetchBody(idHex(seededID(1))))
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("the batch read consulted the freeze gate — reads are never refused")
	}
	if code, ok := decodeBlobs(t, resp, body).omittedCode(idHex(seededID(1))); !ok || code != "not_found" {
		t.Fatalf("frozen read: omitted=%v code=%q, want not_found", ok, code)
	}
}

// A batch READ must not open a store write-batch: on the fs backend that takes a
// write lock and serializes concurrent pullers behind a pure read.
func TestBlobs_OpensNoStoreBatch(t *testing.T) {
	base := store.NewMemStore()
	spy := &batchSpy{BlobStore: base}
	srv, token := setupWith(t, spy)
	defer srv.Close()
	var a ids.AccountNumberHash
	a[0] = 0x42
	id := seededID(1)
	if _, err := base.PushBlob(a, id, 0, [store.ContentNonceLen]byte{}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if resp, b := do(t, srv, http.MethodPost, "/sync/blobs", token, fetchBody(idHex(id))); resp.StatusCode != 200 {
		t.Fatalf("batch fetch: %d %s", resp.StatusCode, b)
	}
	if spy.batches != 0 {
		t.Fatalf("a batch read opened %d store batches, want 0", spy.batches)
	}
}

func TestBlobs_MethodAuthAndBodyPlumbing(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	seedBlobs(t, st, a, 1)
	one := idHex(seededID(1))

	if resp, _ := do(t, srv, http.MethodGet, "/sync/blobs", token, ""); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /sync/blobs: status %d, want 405", resp.StatusCode)
	}
	if resp, _ := do(t, srv, http.MethodPost, "/sync/blobs", "", fetchBody(one)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthed batch: status %d, want 401", resp.StatusCode)
	}
	// An empty list is a 200 with nothing in it, never a 400 and never a 5xx.
	resp, body := do(t, srv, http.MethodPost, "/sync/blobs", token, `{"blob_ids_hex":[]}`)
	br := decodeBlobs(t, resp, body)
	if len(br.Blobs) != 0 || len(br.Omitted) != 0 {
		t.Fatalf("empty request produced %+v", br)
	}
	// A malformed id fails the WHOLE request: answering it per-id would let a
	// client mistake "you sent garbage" for "the server does not have this".
	if resp, _ := do(t, srv, http.MethodPost, "/sync/blobs", token, fetchBody(one, "zz")); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed id: status %d, want 400", resp.StatusCode)
	}
	if resp, _ := do(t, srv, http.MethodPost, "/sync/blobs", token, "not json"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-JSON body: status %d, want 400", resp.StatusCode)
	}
	// The new route must not shadow the single-blob one.
	if resp, _ := do(t, srv, http.MethodGet, "/sync/blob?id="+one, token, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /sync/blob after registering /sync/blobs: status %d, want 200", resp.StatusCode)
	}
}
