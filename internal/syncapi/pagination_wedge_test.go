// SPDX-License-Identifier: AGPL-3.0

package syncapi

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// seedBlobs pushes n distinct live blobs; each push bumps the account's change
// sequence by one, so after this the sequence runs 1..n.
func seedBlobs(t *testing.T, st *store.MemStore, a ids.AccountNumberHash, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		var id ids.BlobID
		id[0] = byte(i >> 8)
		id[1] = byte(i)
		if _, err := st.PushBlob(a, id, 0, [store.ContentNonceLen]byte{}, []byte{byte(i)}); err != nil {
			t.Fatalf("push blob %d: %v", i, err)
		}
	}
}

// The plain (no-reclaim) initial pull of a >256-blob account must paginate and
// drain EVERY page — not stop at page 1. The existing policy tests only ever
// seed two blobs, so the multi-page boundary walk (E2E-gap #1, server half) was
// unexercised at the HTTP layer.
func TestPull_MultiPagePlainDrainsEveryPage(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	const total = DefaultPullLimit + 4 // strictly more than one 256-blob page
	seedBlobs(t, st, a, total)

	seen := map[string]bool{}
	cursor := uint64(0)
	pages := 0
	for pages < 12 {
		resp, body := do(t, srv, http.MethodGet, fmt.Sprintf("/sync/pull?cursor=%d", cursor), token, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("page %d pull status %d, want 200", pages, resp.StatusCode)
		}
		var pr pullResp
		if err := json.Unmarshal(body, &pr); err != nil {
			t.Fatalf("page %d body: %v", pages, err)
		}
		for _, m := range pr.Metas {
			seen[m.UUIDHex] = true
		}
		pages++
		if len(pr.Metas) == 0 || pr.NextCursor == cursor {
			break
		}
		cursor = pr.NextCursor
	}
	if pages < 2 {
		t.Fatalf("expected multi-page pagination, got %d page(s)", pages)
	}
	if len(seen) != total {
		t.Fatalf("drained %d distinct blobs across pages, want %d (a page-1-only bug would show %d)",
			len(seen), total, DefaultPullLimit)
	}
}

// The pagination×GC-floor wedge (E2E-gap #1, the top-ranked critical): a device
// with >256 blobs paginates forward; a reclaim floor sitting BEYOND the page-1
// boundary makes the page-2 forward cursor sub-floor, so the server 410s it —
// and the client MUST recover by flipping to a floor-exempt reconcile walk that
// drains every live blob. Prior tests proved the 410 and the reconcile-exemption
// in ISOLATION with two blobs; this composes them at true multi-page scale.
func TestPull_MultiPageFloorWedgeRecoversViaReconcile(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	const total = DefaultPullLimit + 4
	seedBlobs(t, st, a, total)

	// Page-1 forward pull: a full 256-blob page + a next_cursor at the boundary.
	resp, body := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page-1 status %d, want 200", resp.StatusCode)
	}
	var page1 pullResp
	if err := json.Unmarshal(body, &page1); err != nil {
		t.Fatal(err)
	}
	if len(page1.Metas) != DefaultPullLimit {
		t.Fatalf("page 1 returned %d metas, want %d", len(page1.Metas), DefaultPullLimit)
	}
	boundary := page1.NextCursor // == the change_seq of the 256th blob

	// Advance the reclaim floor BEYOND the page-1 boundary by reclaiming a blob
	// whose change_seq lands on page 2 (blob #total, seq = total > boundary).
	var victim ids.BlobID
	victim[0] = byte(total >> 8)
	victim[1] = byte(total & 0xff)
	if err := st.SetTombstone(a, victim, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.ReclaimTombstone(a, victim); err != nil {
		t.Fatal(err)
	}
	if floor := st.GCFloor(a); floor <= boundary {
		t.Fatalf("reclaim floor %d did not advance beyond the page-1 boundary %d", floor, boundary)
	}

	// The re-paginating device's page-2 forward pull at the (now sub-floor)
	// boundary cursor is rejected 410 cursor_expired — the wedge trigger.
	resp2, _ := do(t, srv, http.MethodGet, fmt.Sprintf("/sync/pull?cursor=%d", boundary), token, "")
	if resp2.StatusCode != http.StatusGone {
		t.Fatalf("forward page-2 pull status %d, want 410 cursor_expired", resp2.StatusCode)
	}

	// Recovery: a full reconcile walk from cursor 0 is floor-exempt and drains
	// every LIVE blob across all pages without wedging.
	seen := map[string]bool{}
	cursor := uint64(0)
	for pages := 0; pages < 12; pages++ {
		r, b := do(t, srv, http.MethodGet, fmt.Sprintf("/sync/pull?cursor=%d&reconcile=1", cursor), token, "")
		if r.StatusCode != http.StatusOK {
			t.Fatalf("reconcile page %d status %d, want 200 (must bypass the floor)", pages, r.StatusCode)
		}
		var pr pullResp
		if err := json.Unmarshal(b, &pr); err != nil {
			t.Fatal(err)
		}
		for _, m := range pr.Metas {
			seen[m.UUIDHex] = true
		}
		if len(pr.Metas) == 0 || pr.NextCursor == cursor {
			break
		}
		cursor = pr.NextCursor
	}
	// The reconcile walk surfaces every LIVE blob across pages; the reclaimed
	// victim is manifest-ABSENT (the client reconstructs the deletion from
	// manifest-absence, sync-protocol §11.2/§11.3), never a size-0 meta. The
	// point is the walk drained past the floor without wedging.
	if len(seen) != total-1 {
		t.Fatalf("reconcile drained %d manifest entries across pages, want %d (live only)", len(seen), total-1)
	}
	if seen[hex.EncodeToString(victim[:])] {
		t.Fatalf("reclaimed blob %x must be absent from the reconcile manifest", victim[:])
	}
	// The drained cursor sits at/above the floor, so the device's next PLAIN
	// incremental pull is served — the recovery truly un-wedges it.
	rf, _ := do(t, srv, http.MethodGet, fmt.Sprintf("/sync/pull?cursor=%d", cursor), token, "")
	if rf.StatusCode != http.StatusOK {
		t.Fatalf("post-reconcile incremental pull status %d, want 200", rf.StatusCode)
	}
}
