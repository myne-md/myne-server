// SPDX-License-Identifier: AGPL-3.0

package syncapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/myne-md/myne-server/internal/ids"
)

// This file is the owner-only namespace-retirement surface (myne-md/myne#711,
// decisions/protocol/0599), plus the vault.meta write gate that shares its
// authority. The route is the one frozen by that decision:
//
//	POST /b2b/vaults/{account_hash}/retire
//
// The server verifies NO signature and holds NO public key. The owner's
// authenticated session is the authority (Grill 4 Q13); the owner-double-signed
// retirement record remains the peer-verifiable artefact and travels the blob
// plane. The server acts on the sync ids the owner names: a write to a retired
// id is refused, and the retired blobs are reclaimed only after the grace.

// bearerHex extracts the raw bearer credential hex without validating it. The
// membership resolver decides whether it is a valid per-vault token.
func bearerHex(r *http.Request) string {
	const pfx = "Bearer "
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, pfx) {
		return ""
	}
	return strings.TrimPrefix(authz, pfx)
}

// vaultMetaWriteAccount resolves the account a vault.meta PUT may write, or
// writes the refusal and returns ok=false.
//
// A vault that has an owner membership binding (a B2B vault) requires the
// OWNER's per-vault token: a member token is refused `403`, and a device token
// is refused too (`owner_required`), because a device token carries no role and
// the roster is owner-authored. A vault with no owner binding (single-user)
// keeps the pre-B2B device-token path unchanged, so no existing vault is
// broken by the B2B gate landing.
func (h *Handler) vaultMetaWriteAccount(w http.ResponseWriter, r *http.Request) (ids.AccountNumberHash, bool) {
	if h.membership != nil {
		if vault, owner, ok := h.membership.ResolveMember(bearerHex(r)); ok {
			if !owner {
				writeErr(w, http.StatusForbidden, "forbidden")
				return ids.AccountNumberHash{}, false
			}
			return vault, true
		}
	}
	sess, authCode := h.sessionWithCode(r)
	if authCode != "" {
		writeErr(w, http.StatusUnauthorized, authCode)
		return ids.AccountNumberHash{}, false
	}
	if h.membership != nil && h.membership.HasOwner(sess.Account) {
		writeErr(w, http.StatusForbidden, "owner_required")
		return ids.AccountNumberHash{}, false
	}
	return sess.Account, true
}

type retireReq struct {
	// RetiredEpoch and ReplacementEpoch are the retirement record's provenance
	// fields (the record itself is 33 bytes and rides the blob plane). The store
	// keeps them so an operator/audit read can see what the owner rotated from
	// and to.
	RetiredEpoch     uint64 `json:"retired_epoch"`
	ReplacementEpoch uint64 `json:"replacement_epoch"`
	NamespaceKind    string `json:"namespace_kind"`
	NamespaceIDHex   string `json:"namespace_id_hex"`
	// ReclaimSyncIDsHex names the OLD sync ids this retirement retires. This is
	// the server's enforcement and reclamation key: a write to one is refused,
	// and its blob is reclaimed after the grace.
	ReclaimSyncIDsHex []string `json:"reclaim_sync_ids_hex"`
}

func (h *Handler) handleRetire(w http.ResponseWriter, r *http.Request) {
	vault, ok := ids.ParseAccountNumberHash(r.PathValue("account_hash"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	if h.membership == nil || h.retirements == nil {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	v, owner, ok := h.membership.ResolveMember(bearerHex(r))
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	if v != vault || !owner {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var req retireReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxVaultMetaSize)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	if req.RetiredEpoch == 0 || req.ReplacementEpoch != req.RetiredEpoch+1 {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	if req.NamespaceKind != "group-key" && req.NamespaceKind != "items-key" {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	nsID, ok := parseBlobID(req.NamespaceIDHex)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	// A group-key retirement names the vault's account hash (protocol
	// `RetiredNamespaceKind`; the same binding the peer verifier enforces). The
	// server checks it too so a retirement copied from another vault is refused
	// here rather than silently recorded.
	if req.NamespaceKind == "group-key" && ids.AccountNumberHash(nsID) != vault {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	reclaim := make([]ids.BlobID, 0, len(req.ReclaimSyncIDsHex))
	for _, s := range req.ReclaimSyncIDsHex {
		id, ok := parseBlobID(s)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad_request")
			return
		}
		reclaim = append(reclaim, id)
	}
	h.retirements.Record(vault, req.RetiredEpoch, req.ReplacementEpoch, reclaim)
	writeJSON(w, map[string]bool{"ok": true})
}
