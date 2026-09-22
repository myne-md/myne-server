// SPDX-License-Identifier: AGPL-3.0

package authapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
)

// This file is the HTTP surface for the B2B person↔vault access model
// (myne-md/myne#711, decisions/protocol/0599). Three facts shape it:
//
//  1. A PERSON ACCOUNT IS AN ACCOUNT IN THE EXISTING SCRAM NAMESPACE. The person's
//     server credential derives on the client from the recovery phrase under
//     `myne.v0.2 argon2id-person-server-auth|` plus `person_id_hash`, and the
//     server is handed only a SCRAM verifier, exactly as for a vault account
//     (server-protocol.md §3.1). So a person account registers and authenticates
//     through /auth/register, /auth/scram/init and /auth/scram/final with
//     `account_hash_hex = person_id_hash`. No separate person-auth route exists,
//     deliberately: the server cannot tell a person id from a vault id and must
//     not, because it is blind to the difference. The id-typed namespace IS the
//     person namespace.
//
//  2. ACCESS TO A VAULT IS A MEMBERSHIP BINDING, NOT A KEY. The person↔vault
//     table (internal/membership) is the server-side availability authority; the
//     server reads no roster plaintext, no fingerprint and no name, and verifies
//     no owner signature. A binding issues a per-vault bearer token scoped to
//     exactly (person, vault), so revoking one binding stops one vault's sync and
//     leaves the person's other vaults untouched.
//
//  3. THE OWNER IS BOOTSTRAPPED BY THE VAULT'S OWN SESSION. A vault keeps its
//     `account_number_hash` as its public id, its storage namespace and its
//     pre-auth GET /vault.meta bootstrap key (server-protocol.md §2.1, §3.1). The
//     owner's device is enrolled on that vault account, so the first
//     `POST /b2b/vaults/{account_hash}/members` for a vault is authorized by the
//     VAULT's device token and binds the owner person ("owner at registration").
//     Every later member-management call is authorized by the OWNER's per-vault
//     membership token, which carries a role rather than a key.
//
// The routes are the ones frozen by decisions/protocol/0599:
//
//	POST   /b2b/vaults/{account_hash}/members
//	DELETE /b2b/vaults/{account_hash}/members/{person_id}
//
// The invite relay routes (POST /b2b/invites, GET /b2b/invites,
// POST /b2b/invites/{invite_id}/claim) are task 8 and are not registered here;
// the owner-only vault.meta refusal and namespace retirement (task 9) consume
// the same membership seam.

// membershipTable returns the person↔vault table for a caller that needs it
// (syncapi's owner-only vault.meta refusal is the next consumer, task 9).
func (h *Handler) Membership() *membership.Table { return h.members }

// memberTokens returns the per-vault token store for a caller that needs it.
func (h *Handler) MemberTokens() *membership.TokenStore { return h.memberTks }

// ResolveMember implements the sync surface's membership seam: it resolves a
// per-vault bearer token to its vault and whether it is the owner's. ok=false
// for anything that is not a membership token (an /auth device token, an
// unknown string), which is how the sync surface distinguishes the two.
func (h *Handler) ResolveMember(bearerHex string) (ids.AccountNumberHash, bool, bool) {
	raw, err := hex.DecodeString(bearerHex)
	if err != nil {
		return ids.AccountNumberHash{}, false, false
	}
	b, err := h.memberTks.Resolve(ids.DeviceToken(raw))
	if err != nil {
		return ids.AccountNumberHash{}, false, false
	}
	return b.Vault, b.Role == membership.RoleOwner, true
}

// HasOwner reports whether a vault has an owner membership binding. It is what
// makes the vault.meta write gate generation-aware without reading the opaque
// blob: a vault with an owner binding is a B2B vault and requires the owner's
// per-vault token; one without keeps the pre-B2B device-token path.
func (h *Handler) HasOwner(vault ids.AccountNumberHash) bool {
	_, ok := h.members.OwnerOf(vault)
	return ok
}

// parsePersonID decodes a 16-byte person_id_hash from lowercase hex. It is the
// person-side twin of parseDevice: person ids are fixed-size and hex-encoded on
// every B2B surface, so a malformed one is a client bug, refused 400.
func parsePersonID(s string) (membership.PersonID, bool) {
	var p membership.PersonID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(p) {
		return p, false
	}
	copy(p[:], b)
	return p, true
}

func roleWire(r membership.Role) string {
	if r == membership.RoleOwner {
		return "owner"
	}
	return "member"
}

func parseRole(s string) (membership.Role, bool) {
	switch s {
	case "owner":
		return membership.RoleOwner, true
	case "member":
		return membership.RoleMember, true
	default:
		return 0, false
	}
}

// bearerToken extracts the raw bearer credential, if any. It does not validate:
// which store a token is resolved against (auth vs membership) is the caller's
// decision, because the two are different authorities.
func bearerToken(r *http.Request) (ids.DeviceToken, bool) {
	const pfx = "Bearer "
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, pfx) {
		return nil, false
	}
	b, err := hex.DecodeString(strings.TrimPrefix(authz, pfx))
	if err != nil {
		return nil, false
	}
	return ids.DeviceToken(b), true
}

type bindMemberReq struct {
	PersonIDHex string `json:"person_id_hex"`
	Role        string `json:"role"`
}

type bindMemberResp struct {
	PersonIDHex string `json:"person_id_hex"`
	Role        string `json:"role"`
	// TokenHex is the per-vault bearer token for the binding just created. It is
	// scoped to exactly (person, vault): it authenticates that person for that
	// vault and nothing else, and Revoke on the binding retires it.
	TokenHex string `json:"token_hex"`
}

// handleBindMember creates a person↔vault binding and issues that binding's
// per-vault token.
//
// Two authorizations are accepted, and they are not interchangeable:
//
//   - The VAULT's own device session (an /auth token resolving to this vault)
//     may register the vault's OWNER, once. This is "owner at registration": the
//     vault account is the pre-existing thing and its device is the credential
//     that proves control of the namespace. It may not add members.
//   - The OWNER's per-vault membership token may add a MEMBER. The owner role is
//     fixed at registration and cannot be re-assigned through this route.
func (h *Handler) handleBindMember(w http.ResponseWriter, r *http.Request) {
	vault, ok := ids.ParseAccountNumberHash(r.PathValue("account_hash"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	var req bindMemberReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxAuthBodySize)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	person, ok := parsePersonID(req.PersonIDHex)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	role, ok := parseRole(req.Role)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	// (1) Owner membership token: may bind members. Resolve is tried first
	// because a membership token is the narrower authority, and a token that
	// resolves here is not an /auth token (the stores are disjoint).
	if b, err := h.memberTks.Resolve(tok); err == nil {
		if b.Vault != vault || b.Role != membership.RoleOwner {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if role != membership.RoleMember {
			// The singleton owner is established by the vault session, never
			// re-assigned by an owner token.
			writeErr(w, http.StatusBadRequest, "bad_request")
			return
		}
		if err := h.members.BindMember(vault, person); err != nil {
			if errors.Is(err, membership.ErrAlreadyBound) {
				writeErr(w, http.StatusConflict, "already_bound")
				return
			}
			writeErr(w, http.StatusBadRequest, "bad_request")
			return
		}
		h.writeIssuedBinding(w, person, vault, role)
		return
	}

	// (2) The vault's own device session: owner registration, first-write only.
	sess, err := h.tokens.AuthenticateSession(tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, auth.FailureCode(err))
		return
	}
	if sess.Account != vault {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if role != membership.RoleOwner {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := h.members.BindOwner(vault, person); err != nil {
		if errors.Is(err, membership.ErrOwnerExists) {
			writeErr(w, http.StatusConflict, "already_owned")
			return
		}
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	h.writeIssuedBinding(w, person, vault, role)
}

func (h *Handler) writeIssuedBinding(w http.ResponseWriter, person membership.PersonID, vault membership.VaultID, role membership.Role) {
	token, err := h.memberTks.Issue(person, vault)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, bindMemberResp{
		PersonIDHex: hex.EncodeToString(person[:]),
		Role:        roleWire(role),
		TokenHex:    hex.EncodeToString(token),
	})
}

// handleRemoveMember revokes one person's access to one vault: the binding is
// deleted and every outstanding token for that (person, vault) is retired. It is
// the targeted revoke — the person's bindings to other vaults and their tokens
// are untouched. The owner cannot be removed through this route (the owner leaves
// only by deleting the vault).
func (h *Handler) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	vault, ok := ids.ParseAccountNumberHash(r.PathValue("account_hash"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	person, ok := parsePersonID(r.PathValue("person_id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	b, err := h.memberTks.Resolve(tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	if b.Vault != vault || b.Role != membership.RoleOwner {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.members.Remove(vault, person); err != nil {
		switch {
		case errors.Is(err, membership.ErrNotBound):
			writeErr(w, http.StatusNotFound, "not_found")
		case errors.Is(err, membership.ErrOwnerNotFound):
			writeErr(w, http.StatusForbidden, "forbidden")
		default:
			writeErr(w, http.StatusBadRequest, "bad_request")
		}
		return
	}
	h.memberTks.Revoke(vault, person)
	// Schedule the removed person's private AI profiles for reclamation after
	// the retention grace (myne-md/myne#711 task 16). No recall claim: this
	// stops future access and deletes the server's copy after the grace; it does
	// not erase anything the person already holds.
	h.scheduleProfileDeletion(vault, person)
	writeJSON(w, map[string]bool{"ok": true})
}
