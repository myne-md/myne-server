// SPDX-License-Identifier: AGPL-3.0-only

package syncapi

import (
	"encoding/base64"
	"encoding/hex"
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

func setupPolicy(t *testing.T, rl RateLimiter, qg QuotaGuard) (*httptest.Server, string, *store.MemStore, ids.AccountNumberHash) {
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
	New(st, ts).WithPolicy(rl, qg).Register(mux)
	return httptest.NewServer(mux), hex.EncodeToString(res.Token), st, a
}

func TestPolicy_QuotaExceeded507(t *testing.T) {
	srv, token, _, _ := setupPolicy(t, nil, gcquota.NewQuotaGuard(10))
	defer srv.Close()
	id := strings.Repeat("aa", 16)
	nonce := strings.Repeat("cb", 24)
	big := base64.StdEncoding.EncodeToString(make([]byte, 20)) // > 10 ceiling
	p := `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonce + `","ciphertext_b64":"` + big + `"}]}`
	resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, p)
	if resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("quota push status %d, want 507", resp.StatusCode)
	}
}

// The quota gate charges a push its GROWTH, not its full size — the same delta the
// store applies to the counter (#10). Charging the whole ciphertext made the gate
// stricter than the accounting it guards: an account at its ceiling could not push
// a shrink, and could not push a deletion either (the tombstone blob is the note
// plus a `deleted:` line, so it is LARGER than the version it replaces). Bytes are
// released only when horizon-GC reclaims a tombstone, and a tombstone exists only
// after the very push the gate refused — so the account was wedged with no
// in-client remedy, and the 507 aborted the whole request, stopping sync wholesale.

// pushOne builds a one-blob push body carrying `size` bytes of opaque ciphertext.
func pushOne(idHex, nonceHex string, base uint64, size int, tombstone bool) string {
	return fmt.Sprintf(
		`{"blobs":[{"blob_id_hex":%q,"base_version":%d,"content_nonce_hex":%q,"ciphertext_b64":%q,"tombstone":%t}]}`,
		idHex, base, nonceHex, base64.StdEncoding.EncodeToString(make([]byte, size)), tombstone)
}

func TestPolicy_ShrinkAtTheCeilingIsAccepted(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, gcquota.NewQuotaGuard(100))
	defer srv.Close()
	id, nonce := strings.Repeat("aa", 16), strings.Repeat("cb", 24)
	if resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, pushOne(id, nonce, 0, 100, false)); resp.StatusCode != http.StatusOK {
		t.Fatalf("fill-to-ceiling push status %d, want 200", resp.StatusCode)
	}
	if q := st.QuotaBytes(a); q != 100 {
		t.Fatalf("quota after fill = %d, want 100 (at the ceiling)", q)
	}
	resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, pushOne(id, nonce, 1, 60, false))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("shrink-at-ceiling push status %d, want 200", resp.StatusCode)
	}
	if q := st.QuotaBytes(a); q != 60 {
		t.Fatalf("quota after shrink = %d, want 60", q)
	}
}

func TestPolicy_DeletionNearTheCeilingIsAccepted(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, gcquota.NewQuotaGuard(100))
	defer srv.Close()
	id, nonce := strings.Repeat("aa", 16), strings.Repeat("cb", 24)
	if resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, pushOne(id, nonce, 0, 90, false)); resp.StatusCode != http.StatusOK {
		t.Fatalf("fill push status %d, want 200", resp.StatusCode)
	}
	// The deletion re-pushes the note plus its `deleted:` line: 6 bytes bigger than
	// the version it replaces, which is 84 bytes short of what the old gate charged.
	resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, pushOne(id, nonce, 1, 96, true))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deletion push status %d, want 200", resp.StatusCode)
	}
	if q := st.QuotaBytes(a); q != 96 {
		t.Fatalf("quota after deletion = %d, want 96", q)
	}
	var bid ids.BlobID
	for i := range bid {
		bid[i] = 0xaa
	}
	if _, marked := st.Tombstone(a, bid); !marked {
		t.Fatal("no tombstone recorded — horizon-GC has nothing to reclaim, so the bytes never come back")
	}
}

func TestPolicy_GrowthPastTheCeilingIsStillRefused(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, gcquota.NewQuotaGuard(100))
	defer srv.Close()
	id, nonce := strings.Repeat("aa", 16), strings.Repeat("cb", 24)
	if resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, pushOne(id, nonce, 0, 90, false)); resp.StatusCode != http.StatusOK {
		t.Fatalf("fill push status %d, want 200", resp.StatusCode)
	}
	// Replacing 90 bytes with 120 grows the account by 30 past a ceiling of 100.
	resp, _ := do(t, srv, http.MethodPost, "/sync/push", token, pushOne(id, nonce, 1, 120, false))
	if resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("over-ceiling growth status %d, want 507", resp.StatusCode)
	}
	if q := st.QuotaBytes(a); q != 90 {
		t.Fatalf("quota after refused push = %d, want 90 (nothing stored)", q)
	}
}

func TestPolicy_RateLimited429(t *testing.T) {
	srv, token, _, _ := setupPolicy(t, gcquota.NewRateLimiter(1, 0), nil)
	defer srv.Close()
	if resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", token, ""); resp.StatusCode != 200 {
		t.Fatalf("first pull status %d, want 200", resp.StatusCode)
	}
	if resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", token, ""); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second pull status %d, want 429", resp.StatusCode)
	}
}

func TestPolicy_CursorExpired410(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	// Drive the store to a reclaim floor of 2: two blobs, tombstone the second, reclaim it.
	_, _ = st.PushBlob(a, ids.BlobID{0x01}, 0, [store.ContentNonceLen]byte{}, []byte("a"))
	_, _ = st.PushBlob(a, ids.BlobID{0x02}, 0, [store.ContentNonceLen]byte{}, []byte("b"))
	_ = st.SetTombstone(a, ids.BlobID{0x02}, 1)
	_ = st.ReclaimTombstone(a, ids.BlobID{0x02}) // floor → 2
	if st.GCFloor(a) != 2 {
		t.Fatalf("GCFloor = %d, want 2", st.GCFloor(a))
	}
	// Pull with a cursor below the floor → 410 cursor_expired.
	resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=1", token, "")
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("stale-cursor pull status %d, want 410", resp.StatusCode)
	}
}

// A reconcile-mode pull is the client walking the whole manifest, so a sub-floor
// cursor must be SERVED (not 410'd) — otherwise a vault whose reclaim floor sits
// beyond the first pull page wedges any re-paginating device on page 2 forever.
func TestPolicy_ReconcileBypassesFloor(t *testing.T) {
	srv, token, st, a := setupPolicy(t, nil, nil)
	defer srv.Close()
	_, _ = st.PushBlob(a, ids.BlobID{0x01}, 0, [store.ContentNonceLen]byte{}, []byte("a"))
	_, _ = st.PushBlob(a, ids.BlobID{0x02}, 0, [store.ContentNonceLen]byte{}, []byte("b"))
	_ = st.SetTombstone(a, ids.BlobID{0x02}, 1)
	_ = st.ReclaimTombstone(a, ids.BlobID{0x02}) // floor → 2
	if st.GCFloor(a) != 2 {
		t.Fatalf("GCFloor = %d, want 2", st.GCFloor(a))
	}
	// Same sub-floor cursor, but reconcile=1 → served, not rejected.
	resp, _ := do(t, srv, http.MethodGet, "/sync/pull?cursor=1&reconcile=1", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reconcile sub-floor pull status %d, want 200", resp.StatusCode)
	}
}
