// SPDX-License-Identifier: AGPL-3.0

package syncapi

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// fakeMembership is the sync surface's view of the B2B membership authority: it
// resolves two fixed per-vault bearers and reports whether a vault has an owner.
type fakeMembership struct {
	ownerBearer  string
	memberBearer string
	vault        ids.AccountNumberHash
	owners       map[ids.AccountNumberHash]bool
}

func (f *fakeMembership) ResolveMember(bearerHex string) (ids.AccountNumberHash, bool, bool) {
	switch bearerHex {
	case f.ownerBearer:
		return f.vault, true, true
	case f.memberBearer:
		return f.vault, false, true
	default:
		return ids.AccountNumberHash{}, false, false
	}
}

func (f *fakeMembership) HasOwner(v ids.AccountNumberHash) bool { return f.owners[v] }

// setupB2B wires a sync handler with a fake membership authority and a
// retirement registry. withOwner controls whether the vault is a B2B vault (an
// owner binding exists) or a single-user vault.
func setupB2B(t *testing.T, grace time.Duration, withOwner bool) (srv *httptest.Server, owner, member, device string, vault ids.AccountNumberHash, rets *store.Retirements) {
	t.Helper()
	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)
	vault[0] = 0x42
	var d ids.DeviceID
	d[0] = 0x01
	res, err := en.Enroll(vault, d, auth.PathPassword) // first device → token
	if err != nil {
		t.Fatal(err)
	}
	owners := map[ids.AccountNumberHash]bool{}
	if withOwner {
		owners[vault] = true
	}
	fm := &fakeMembership{
		ownerBearer:  strings.Repeat("aa", 32),
		memberBearer: strings.Repeat("bb", 32),
		vault:        vault,
		owners:       owners,
	}
	rets = store.NewRetirements(grace)
	mux := http.NewServeMux()
	New(st, ts).WithMembership(fm).WithRetirements(rets).Register(mux)
	return httptest.NewServer(mux), fm.ownerBearer, fm.memberBearer, hex.EncodeToString(res.Token), vault, rets
}

func retireBody(t *testing.T, vault ids.AccountNumberHash, reclaimIDs ...string) string {
	t.Helper()
	return mustJSON(t, retireReq{
		RetiredEpoch:      1,
		ReplacementEpoch:  2,
		NamespaceKind:     "group-key",
		NamespaceIDHex:    hex.EncodeToString(vault[:]),
		ReclaimSyncIDsHex: reclaimIDs,
	})
}

func pushBlobForRetire(t *testing.T, srv *httptest.Server, token, idHex string) (*http.Response, []byte) {
	t.Helper()
	req := pushReq{Blobs: []pushBlob{{
		BlobIDHex:     idHex,
		BaseVersion:   0,
		ContentNonce:  nonceHex(1),
		CiphertextB64: base64.StdEncoding.EncodeToString([]byte("ciphertext")),
	}}}
	return do(t, srv, http.MethodPost, "/sync/push", token, mustJSON(t, req))
}

func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var eb errBody
	if err := json.Unmarshal(body, &eb); err != nil {
		t.Fatalf("error body %s: %v", body, err)
	}
	return eb.ErrorCode
}

func TestRetire_OnlyOwnerCanRetire(t *testing.T) {
	srv, owner, member, _, vault, _ := setupB2B(t, time.Hour, true)
	defer srv.Close()
	path := "/b2b/vaults/" + hex.EncodeToString(vault[:]) + "/retire"
	body := retireBody(t, vault, pushBlobIDHex(9))

	if resp, _ := do(t, srv, http.MethodPost, path, "", body); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no bearer: want 401, got %d", resp.StatusCode)
	}
	if resp, _ := do(t, srv, http.MethodPost, path, member, body); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member token retiring: want 403, got %d", resp.StatusCode)
	}
	// The owner token is for vault 0x42; the path names a DIFFERENT vault, which
	// the owner does not own.
	other := ids.AccountNumberHash{}
	other[0] = 0x99
	otherPath := "/b2b/vaults/" + hex.EncodeToString(other[:]) + "/retire"
	if resp, _ := do(t, srv, http.MethodPost, otherPath, owner, body); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("owner token against another vault: want 403, got %d", resp.StatusCode)
	}
	if resp, b := do(t, srv, http.MethodPost, path, owner, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("owner retire: want 200, got %d: %s", resp.StatusCode, b)
	}
}

// A group-key retirement names the vault's account hash; a retirement copied
// from another vault must be refused here, not silently recorded.
func TestRetire_GroupKeyNamespaceMustBindVault(t *testing.T) {
	srv, owner, _, _, vault, _ := setupB2B(t, time.Hour, true)
	defer srv.Close()
	path := "/b2b/vaults/" + hex.EncodeToString(vault[:]) + "/retire"
	wrong := ids.AccountNumberHash{}
	wrong[0] = 0x77
	body := mustJSON(t, retireReq{
		RetiredEpoch: 1, ReplacementEpoch: 2, NamespaceKind: "group-key",
		NamespaceIDHex: hex.EncodeToString(wrong[:]),
	})
	if resp, _ := do(t, srv, http.MethodPost, path, owner, body); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("group-key retirement for another vault: want 400, got %d", resp.StatusCode)
	}
	// An items-key retirement may name any id (the server does not know the
	// vault's items_key_id and does not need it).
	okBody := mustJSON(t, retireReq{
		RetiredEpoch: 1, ReplacementEpoch: 2, NamespaceKind: "items-key",
		NamespaceIDHex: hex.EncodeToString(wrong[:]),
	})
	if resp, b := do(t, srv, http.MethodPost, path, owner, okBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("items-key retirement: want 200, got %d: %s", resp.StatusCode, b)
	}
	// A malformed epoch pair is refused.
	badEpoch := mustJSON(t, retireReq{
		RetiredEpoch: 1, ReplacementEpoch: 5, NamespaceKind: "items-key",
		NamespaceIDHex: hex.EncodeToString(wrong[:]),
	})
	if resp, _ := do(t, srv, http.MethodPost, path, owner, badEpoch); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-consecutive epochs: want 400, got %d", resp.StatusCode)
	}
}

// The owner retires the OLD sync ids; a later write to one is refused, and a
// write to a live id still succeeds.
func TestRetire_RetiredNamespaceWriteRefused(t *testing.T) {
	srv, owner, _, device, vault, _ := setupB2B(t, time.Hour, true)
	defer srv.Close()
	retired := pushBlobIDHex(9)
	live := pushBlobIDHex(10)
	path := "/b2b/vaults/" + hex.EncodeToString(vault[:]) + "/retire"

	if resp, b := do(t, srv, http.MethodPost, path, owner, retireBody(t, vault, retired)); resp.StatusCode != http.StatusOK {
		t.Fatalf("retire: want 200, got %d: %s", resp.StatusCode, b)
	}
	resp, body := pushBlobForRetire(t, srv, device, retired)
	if resp.StatusCode != http.StatusConflict || errorCode(t, body) != "retired" {
		t.Fatalf("push to a retired id: want 409 retired, got %d %s", resp.StatusCode, body)
	}
	if resp, body := pushBlobForRetire(t, srv, device, live); resp.StatusCode != http.StatusOK {
		t.Fatalf("push to a live id must still work: got %d %s", resp.StatusCode, body)
	}
}

// The server holds no public key and verifies no signature: the retire body has
// no signature field, and an unknown one is ignored. The owner's authenticated
// session is the whole authority (Grill 4 Q13).
func TestRetire_DoesNotVerifyASignature(t *testing.T) {
	srv, owner, _, _, vault, _ := setupB2B(t, time.Hour, true)
	defer srv.Close()
	path := "/b2b/vaults/" + hex.EncodeToString(vault[:]) + "/retire"
	body := `{"retired_epoch":1,"replacement_epoch":2,"namespace_kind":"group-key","namespace_id_hex":"` +
		hex.EncodeToString(vault[:]) + `","reclaim_sync_ids_hex":[],"signature_hex":"deadbeef"}`
	if resp, b := do(t, srv, http.MethodPost, path, owner, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("retire with an ignored signature field: want 200, got %d: %s", resp.StatusCode, b)
	}
}

// A B2B vault requires the OWNER's per-vault token to write vault.meta: a device
// token carries no role and a member token is refused.
func TestVaultMeta_OwnerTokenRequiredForB2BVault(t *testing.T) {
	srv, owner, member, device, _, _ := setupB2B(t, time.Hour, true)
	defer srv.Close()

	if resp, b := do(t, srv, http.MethodPut, "/vault.meta", device, "meta"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("device-token vault.meta PUT on a B2B vault: want 403, got %d: %s", resp.StatusCode, b)
	}
	if resp, _ := do(t, srv, http.MethodPut, "/vault.meta", member, "meta"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member-token vault.meta PUT: want 403, got %d", resp.StatusCode)
	}
	if resp, b := do(t, srv, http.MethodPut, "/vault.meta", owner, "meta"); resp.StatusCode != http.StatusOK {
		t.Fatalf("owner-token vault.meta PUT: want 200, got %d: %s", resp.StatusCode, b)
	}
}

// A single-user vault (no owner binding) keeps the pre-B2B device-token path,
// so the B2B gate landing breaks no existing vault.
// A member's per-vault membership token now authorizes the vault's sync
// namespace (myne-md/myne#711 task 24): a B2B member has no device token on the
// vault account, so push and pull must accept the membership token. The
// vault.meta gate above still refuses it for the credential blob.
func TestMemberTokenAuthorizesSyncNamespace(t *testing.T) {
	srv, _, member, _, _, _ := setupB2B(t, time.Hour, true)
	defer srv.Close()

	if resp, b := pushBlobForRetire(t, srv, member, pushBlobIDHex(5)); resp.StatusCode != http.StatusOK {
		t.Fatalf("member content push: want 200, got %d: %s", resp.StatusCode, b)
	}
	if resp, b := do(t, srv, http.MethodGet, "/sync/pull?cursor=0", member, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("member pull: want 200, got %d: %s", resp.StatusCode, b)
	}
}

func TestVaultMeta_SingleUserVaultKeepsDeviceToken(t *testing.T) {
	srv, _, _, device, _, _ := setupB2B(t, time.Hour, false)
	defer srv.Close()
	if resp, b := do(t, srv, http.MethodPut, "/vault.meta", device, "meta"); resp.StatusCode != http.StatusOK {
		t.Fatalf("device-token vault.meta PUT on a single-user vault: want 200, got %d: %s", resp.StatusCode, b)
	}
}
