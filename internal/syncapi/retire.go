// SPDX-License-Identifier: AGPL-3.0

package syncapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
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
		if b, ok := h.membership.ResolveMember(bearerHex(r)); ok {
			if b.Role != membership.RoleOwner {
				writeErr(w, http.StatusForbidden, "forbidden")
				return ids.AccountNumberHash{}, false
			}
			// The registry answer applies here too: an owner token on a revoked
			// device must not keep writing the credential blob after the device
			// was removed (myne-md/myne#911 task 9).
			if b.Device != (ids.DeviceID{}) && b.Account != (ids.AccountNumberHash{}) && !h.membership.DeviceActive(b.Account, ids.DeviceID(b.Device)) {
				writeErr(w, http.StatusUnauthorized, "device_revoked")
				return ids.AccountNumberHash{}, false
			}
			return b.Vault, true
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

// vaultMetaPublishAccount is the vault.meta PUT path for a PERSON session that
// names a vault (`?account=`, myne-md/myne#911 task 7).
//
// Publishing is the act that makes a device-local vault a server vault, so it is
// also the act that records who owns it: owner-at-first-write, the rule §3.1a
// already applies to `POST /b2b/vaults/{h}/members`. The three answers, in this
// order, and the order is the authority:
//
//  1. The vault has an owner and it is this person: write.
//  2. The vault has an owner and it is someone else: `403 forbidden`. This is
//     the case a cross-tenant publish would hit, and it is checked BEFORE any
//     write so a refused publish leaves no trace.
//  3. The vault has no owner: bind this person as the owner, then write. A vault
//     that already has blobs but no owner is a pre-B2B vault whose first B2B act
//     is this publish, which is the same first-write-only transition the
//     membership route performs.
//
// A selector naming the caller's OWN account never reaches here: that is a vault
// device token addressing its own namespace, and `vaultMetaWriteAccount`'s
// existing gate owns it.
func (h *Handler) vaultMetaPublishAccount(w http.ResponseWriter, r *http.Request, vault ids.AccountNumberHash) (ids.AccountNumberHash, bool) {
	if h.membership == nil {
		writeErr(w, http.StatusForbidden, "forbidden")
		return ids.AccountNumberHash{}, false
	}
	sess, authCode := h.sessionWithCode(r)
	if authCode != "" {
		writeErr(w, http.StatusUnauthorized, authCode)
		return ids.AccountNumberHash{}, false
	}
	if vault == sess.Account {
		// The vault's own device token naming itself: the legacy path.
		if h.membership.HasOwner(vault) {
			writeErr(w, http.StatusForbidden, "owner_required")
			return ids.AccountNumberHash{}, false
		}
		return vault, true
	}
	owner, bound := h.membership.BoundTo(vault, sess.Account)
	if bound {
		if !owner {
			writeErr(w, http.StatusForbidden, "forbidden")
			return ids.AccountNumberHash{}, false
		}
		return vault, true
	}
	if h.membership.HasOwner(vault) {
		// Someone else's vault. Same refusal a non-owner member gets, so the
		// route is not an oracle for "this vault exists and has an owner".
		writeErr(w, http.StatusForbidden, "forbidden")
		return ids.AccountNumberHash{}, false
	}
	// Owner-at-first-write binds a VIRGIN namespace only (myne-md/myne#911
	// review). A namespace that already holds a `vault.meta` has an owner even
	// when the binding table does not know it: every pre-B2B vault is ownerless
	// in the table, and its namespace is its account number, which this change
	// reclassifies as an identifier rather than a credential. Binding it on the
	// strength of knowing a number would let any person account claim someone
	// else's vault and overwrite the one blob every other device bootstraps from.
	// A peer that genuinely has to publish an existing vault proves it the way it
	// always did: with that vault's own device session, which the selector-less
	// arm above owns.
	if _, err := h.store.GetMeta(vault); err == nil {
		writeErr(w, http.StatusForbidden, "owner_required")
		return ids.AccountNumberHash{}, false
	}
	if err := h.membership.BindOwner(vault, sess.Account); err != nil {
		writeErr(w, http.StatusConflict, "already_owned")
		return ids.AccountNumberHash{}, false
	}
	return vault, true
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
	b, ok := h.membership.ResolveMember(bearerHex(r))
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	if b.Device != (ids.DeviceID{}) && b.Account != (ids.AccountNumberHash{}) && !h.membership.DeviceActive(b.Account, ids.DeviceID(b.Device)) {
		writeErr(w, http.StatusUnauthorized, "device_revoked")
		return
	}
	if b.Vault != vault || b.Role != membership.RoleOwner {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	// The sync routes' per-account bucket, consulted here like every other write on this mux
	// (myne-md/myne-server#18). The key is the VAULT, which is the binding the owner's
	// membership token authorises against, and the bucket is the same one the rest of the
	// surface uses rather than a second, unbounded path into the store.
	if h.rl != nil && !h.rl.Allow(vault) {
		writeErr(w, http.StatusTooManyRequests, "rate")
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
