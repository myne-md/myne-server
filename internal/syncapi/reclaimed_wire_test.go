// SPDX-License-Identifier: AGPL-3.0

package syncapi

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/gcquota"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// seededID reconstructs the blob id seedBlobs assigned to push #i.
func seededID(i int) ids.BlobID {
	var id ids.BlobID
	id[0] = byte(i >> 8)
	id[1] = byte(i)
	return id
}

// F2 regression pin: reclaim the record with the HIGHEST change-sequence. Its
// meta must vanish from every pull page, but next_cursor must still advance
// ACROSS it — a cursor stalled below the reclaim floor would 410 every later
// incremental pull, wedging the device in an unbreakable reconcile loop.
func TestPull_ReclaimedMetaOmittedButCursorAdvances(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	const total = 8
	seedBlobs(t, st, a, total)

	victim := seededID(total) // change_seq == total, the window's highest
	victimHex := hex.EncodeToString(victim[:])
	if err := st.SetTombstone(a, victim, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.ReclaimTombstone(a, victim); err != nil {
		t.Fatal(err)
	}

	// Plain pull from 0: the reclaimed meta is omitted, the cursor is not.
	resp, body := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("plain pull status %d, want 200", resp.StatusCode)
	}
	var pr pullResp
	if err := json.Unmarshal(body, &pr); err != nil {
		t.Fatal(err)
	}
	if len(pr.Metas) != total-1 {
		t.Fatalf("plain pull listed %d metas, want %d (reclaimed omitted)", len(pr.Metas), total-1)
	}
	for _, m := range pr.Metas {
		if m.UUIDHex == victimHex {
			t.Fatalf("reclaimed blob %s still listed in a plain pull", victimHex)
		}
	}
	if floor := st.GCFloor(a); pr.NextCursor < floor {
		t.Fatalf("next_cursor %d stalled below the reclaim floor %d", pr.NextCursor, floor)
	}

	// The reconcile walk must not surface the reclaimed uuid either —
	// deletions reconstruct from manifest-absence (§11.2), not from a marker.
	rresp, rbody := do(t, srv, http.MethodGet, "/sync/pull?cursor=0&reconcile=1", token, "")
	if rresp.StatusCode != http.StatusOK {
		t.Fatalf("reconcile pull status %d, want 200", rresp.StatusCode)
	}
	var rpr pullResp
	if err := json.Unmarshal(rbody, &rpr); err != nil {
		t.Fatal(err)
	}
	for _, m := range rpr.Metas {
		if m.UUIDHex == victimHex {
			t.Fatalf("reclaimed blob %s still listed in a reconcile pull", victimHex)
		}
	}

	// The follow-up incremental pull at the drained cursor is served — the F2
	// pin: with a stalled cursor this would be 410 cursor_expired forever.
	fresp, _ := do(t, srv, http.MethodGet, fmt.Sprintf("/sync/pull?cursor=%d", pr.NextCursor), token, "")
	if fresp.StatusCode != http.StatusOK {
		t.Fatalf("incremental pull at drained cursor status %d, want 200", fresp.StatusCode)
	}
}

// A tombstoned-but-NOT-reclaimed record keeps propagating: the deleted-marked
// version is how other devices learn the deletion (§11.1), and its body is
// still served. Only Layer-2 reclamation makes it manifest-absent.
func TestPull_TombstonedNotReclaimedStillListed(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	seedBlobs(t, st, a, 3)

	victim := seededID(3)
	victimHex := hex.EncodeToString(victim[:])
	if err := st.SetTombstone(a, victim, 1); err != nil {
		t.Fatal(err)
	}

	resp, body := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pull status %d, want 200", resp.StatusCode)
	}
	var pr pullResp
	if err := json.Unmarshal(body, &pr); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range pr.Metas {
		if m.UUIDHex == victimHex {
			found = true
		}
	}
	if !found {
		t.Fatalf("tombstoned (unreclaimed) blob %s missing from pull metas", victimHex)
	}

	// The body still downloads as real bytes — nothing reclaimed yet.
	bresp, bbody := do(t, srv, http.MethodGet, "/sync/blob?id="+victimHex, token, "")
	if bresp.StatusCode != http.StatusOK {
		t.Fatalf("tombstoned blob GET status %d, want 200", bresp.StatusCode)
	}
	var br blobResp
	if err := json.Unmarshal(bbody, &br); err != nil {
		t.Fatal(err)
	}
	ct, err := base64.StdEncoding.DecodeString(br.CiphertextB64)
	if err != nil || !bytes.Equal(ct, []byte{3}) {
		t.Fatalf("tombstoned blob body = %v (err=%v), want the seeded bytes", ct, err)
	}
}

// The three GET /sync/blob outcomes: live → 200 with real bytes, reclaimed →
// fail-closed 410 blob_reclaimed (never a live-looking empty 200 the puller
// would write over a real note), absent → 404.
func TestBlob_Reclaimed410_Missing404_Live200(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	seedBlobs(t, st, a, 2)

	victim := seededID(2)
	if err := st.SetTombstone(a, victim, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.ReclaimTombstone(a, victim); err != nil {
		t.Fatal(err)
	}

	// Live blob: 200 + the seeded ciphertext.
	live := seededID(1)
	lresp, lbody := do(t, srv, http.MethodGet, "/sync/blob?id="+hex.EncodeToString(live[:]), token, "")
	if lresp.StatusCode != http.StatusOK {
		t.Fatalf("live blob status %d, want 200", lresp.StatusCode)
	}
	var lr blobResp
	if err := json.Unmarshal(lbody, &lr); err != nil {
		t.Fatal(err)
	}
	if ct, err := base64.StdEncoding.DecodeString(lr.CiphertextB64); err != nil || !bytes.Equal(ct, []byte{1}) {
		t.Fatalf("live blob body = %v (err=%v), want the seeded bytes", ct, err)
	}

	// Reclaimed blob: 410 with the blob_reclaimed error code.
	rresp, rbody := do(t, srv, http.MethodGet, "/sync/blob?id="+hex.EncodeToString(victim[:]), token, "")
	if rresp.StatusCode != http.StatusGone {
		t.Fatalf("reclaimed blob status %d, want 410", rresp.StatusCode)
	}
	var eb errBody
	if err := json.Unmarshal(rbody, &eb); err != nil {
		t.Fatal(err)
	}
	if eb.ErrorCode != "blob_reclaimed" {
		t.Fatalf("reclaimed blob error_code %q, want blob_reclaimed", eb.ErrorCode)
	}

	// Never-existed blob: 404.
	var missing ids.BlobID
	missing[0] = 0xFF
	mresp, _ := do(t, srv, http.MethodGet, "/sync/blob?id="+hex.EncodeToString(missing[:]), token, "")
	if mresp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing blob status %d, want 404", mresp.StatusCode)
	}
}

// F3 at the wire: a push that advances a tombstoned record's version (the
// legitimate conflict-resurrection case) clears the tombstone record, so a
// later GC pass has nothing to reclaim and the resurrected body survives.
func TestPush_AfterVersionAdvanceTombstoneCleared(t *testing.T) {
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

	seedBlobs(t, st, a, 1)
	id := seededID(1)
	if err := st.SetTombstone(a, id, 1); err != nil {
		t.Fatal(err)
	}

	// Push a NEW content version over the tombstoned record (base 1, fresh nonce).
	idHex := hex.EncodeToString(id[:])
	nonceHex := strings.Repeat("ab", 24)
	ct := base64.StdEncoding.EncodeToString([]byte("resurrected"))
	p := `{"blobs":[{"blob_id_hex":"` + idHex + `","base_version":1,"content_nonce_hex":"` + nonceHex + `","ciphertext_b64":"` + ct + `"}]}`
	resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resurrection push status %d, want 200", resp.StatusCode)
	}
	if _, _, _, ok := st.TombstoneRecord(a, id); ok {
		t.Fatal("tombstone record survived the version advance")
	}

	// Even fully acked (the ack gate would NOT protect it), a GC pass reclaims
	// nothing — the tombstone is gone and the body stays.
	st.AckCursor(a, d, 10)
	g := gcquota.NewHorizonGC(st, reg, gcquota.DefaultPolicy())
	if rec, _ := g.Run(a, 100); rec != 0 {
		t.Fatalf("GC reclaimed %d after resurrection, want 0", rec)
	}
	if body, _, err := st.GetBlob(a, id); err != nil || string(body) != "resurrected" {
		t.Fatalf("resurrected body damaged: %q err=%v", body, err)
	}
}
