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
func (h *Handler) ResolveMember(bearerHex string) (membership.Binding, bool) {
	raw, err := hex.DecodeString(bearerHex)
	if err != nil {
		return membership.Binding{}, false
	}
	b, err := h.memberTks.Resolve(ids.DeviceToken(raw))
	if err != nil {
		return membership.Binding{}, false
	}
	return b, true
}

// DeviceActive implements the sync surface's revocation seam (myne-md/myne#911
// task 9): a device that the owner removed stops authenticating EVERY credential
// it holds, including the per-vault tokens it joined shared vaults with.
//
// Read from the device registry, which is already the authority every
// `AuthenticateSession` call consults, so a device revocation and a membership
// revocation cannot disagree. An unknown device, an unapproved one (still
// pending) and a retired one all answer false; `device_revoked` is the code the
// caller returns, which is the honest one for all three from the vault's side.
//
// `account` is the SCRAM account the device is REGISTERED under, which is what the
// registry is keyed by. It is deliberately not the person holding the binding:
// a shared vault's owner binding is minted by the vault's own device session, so
// the account is the vault's and the person is the owner's, and asking about the
// person made every owner `vault.meta` write answer `device_revoked` for a live
// device (myne-md/myne#911 follow-up).
func (h *Handler) DeviceActive(account ids.AccountNumberHash, device ids.DeviceID) bool {
	rec, ok := h.reg.Get(account, device)
	if !ok {
		return false
	}
	return rec.Approved && !rec.Retired
}

// BoundTo implements the sync surface's person-selector seam (myne-md/myne#911
// task 7): it answers whether `person` holds a binding to `vault`.
//
// `person` arrives as an account id because the server cannot tell a person id
// from a vault id, and does not try. The table is keyed by person, so an account
// that is actually a vault id simply has no binding and the answer is false.
func (h *Handler) BoundTo(vault, person ids.AccountNumberHash) (bool, bool) {
	if h.members == nil {
		return false, false
	}
	role, ok := h.members.Role(vault, membership.PersonID(person))
	return role == membership.RoleOwner, ok
}

// BindOwner implements the publish half of the same seam: a person publishing a
// vault it owns binds itself as the owner (owner-at-first-write, §3.1a).
func (h *Handler) BindOwner(vault, person ids.AccountNumberHash) error {
	if h.members == nil {
		return membership.ErrNotBound
	}
	return h.members.BindOwner(vault, membership.PersonID(person))
}

// HasOwner reports whether a vault has an owner membership binding. It is what
// makes the vault.meta write gate generation-aware without reading the opaque
// blob: a vault with an owner binding is a B2B vault and requires the owner's
// per-vault token; one without keeps the pre-B2B device-token path.
func (h *Handler) HasOwner(vault ids.AccountNumberHash) bool {
	_, ok := h.members.OwnerOf(vault)
	return ok
}

// OwnedVaults implements the status-aggregate half of the membership seam
// (myne-md/myne#911 task 11): the vaults `person` OWNS, and nothing else.
//
// Filtered to `RoleOwner` on purpose. `Table.Vaults` returns every binding,
// including the vaults this person merely joined, and a member's bytes are the
// owner's to free: reporting them as the member's usage would show a figure the
// member cannot act on and that the owner's own account already counts.
func (h *Handler) OwnedVaults(person ids.AccountNumberHash) []ids.AccountNumberHash {
	if h.members == nil {
		return nil
	}
	bindings := h.members.Vaults(membership.PersonID(person))
	var out []ids.AccountNumberHash
	for _, b := range bindings {
		if b.Role == membership.RoleOwner {
			out = append(out, b.Vault)
		}
	}
	return out
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
// Three authorizations are accepted, and they are not interchangeable:
//
//   - The VAULT's own device session (an /auth token resolving to this vault)
//     may register the vault's OWNER, once. This is "owner at registration": the
//     vault account is the pre-existing thing and its device is the credential
//     that proves control of the namespace. It may not add members.
//   - The OWNER's per-vault membership token may add a MEMBER. The owner role is
//     fixed at registration and cannot be re-assigned through this route.
//   - The OWNER's own PERSON session may do both of the above for a vault born
//     under an identity (`NTV7`, myne-md/myne#911): such a vault has no vault
//     device session, so the first arm cannot reach it, and its owner holds no
//     per-vault token yet, so the second cannot either. See
//     `bindByPersonSession` for the two things this arm will and will not do.
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
		// Attributed to the device that OWNS the owner token that asked, which is
		// this physical device: the owner token was issued to a device, and the
		// member token it mints lives and dies with it (myne-md/myne#911 task 9).
		// Its account travels with it for the same reason the device does: it is what
		// the revocation check asks the registry about.
		h.writeIssuedBinding(w, person, vault, role, ids.DeviceID(b.Device), b.Account)
		return
	}

	// (2) The vault's own device session: owner registration, first-write only.
	sess, err := h.tokens.AuthenticateSession(tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, auth.FailureCode(err))
		return
	}
	if sess.Account != vault {
		// Not the vault's own device, so this is a PERSON session. For a vault born
		// under an identity that is the only credential that exists; for any other
		// vault the membership table refuses it, so one arm serves both and the
		// refusal is the same `forbidden` arm (1) answers.
		h.bindByPersonSession(w, sess, vault, person, role)
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
	h.writeIssuedBinding(w, person, vault, role, sess.Device, sess.Account)
}

// bindByPersonSession authorizes a binding request made by the OWNER's own
// PERSON session, the shape a vault born under an identity needs (`NTV7`).
//
// **Why this arm exists.** A born-`NTV7` vault has no vault device session (it is
// never enrolled under a vault account: it is published under the person's
// namespace instead) and its owner holds no per-vault token until one is minted
// here, so arms (1) and (2) are both unreachable on that generation by
// construction rather than by accident. `decisions/storage/0723` makes `NTV7` the
// birth format, so without this arm a vault created today could never be shared
// while `NTV5` was still being written, and none at all once it retires.
//
// **What it will do.** Bind a MEMBER, when the caller is the vault's recorded
// owner in the membership table; and re-mint the owner's OWN binding token, which
// is idempotent and is what the client's `ensure_owner_member_token` needs after a
// restart (that token is device-local state and can be lost).
//
// **What it will not do.** It cannot CREATE the owner binding. The owner is
// established by the publish act (`PUT /vault.meta?account=`, owner-at-first-write)
// or by arm (2), so a person session cannot claim a vault it was not already bound
// to. That is the same authority `BoundTo` gives the sync surface, so publishing
// and sharing cannot disagree about who owns a vault.
//
// The token it mints records the asking device and the session's account exactly
// as arm (1) does, so one device revocation still ends every vault that device
// reached.
func (h *Handler) bindByPersonSession(w http.ResponseWriter, sess auth.Session, vault membership.VaultID, person membership.PersonID, role membership.Role) {
	if h.members == nil {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	// `owner` is the ROLE answer, not merely "bound": a member's own session must
	// not add members to the vault it joined, so the role is checked explicitly.
	owner, bound := h.BoundTo(vault, sess.Account)
	if !bound || !owner {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	switch role {
	case membership.RoleMember:
		if err := h.members.BindMember(vault, person); err != nil {
			if errors.Is(err, membership.ErrAlreadyBound) {
				writeErr(w, http.StatusConflict, "already_bound")
				return
			}
			writeErr(w, http.StatusBadRequest, "bad_request")
			return
		}
	default:
		// Re-minting the owner's OWN token only. A second person cannot be made
		// owner through any route: the singleton owner rule is what makes the
		// client's roster authority answerable.
		if person != membership.PersonID(sess.Account) {
			writeErr(w, http.StatusBadRequest, "bad_request")
			return
		}
	}
	h.writeIssuedBinding(w, person, vault, role, sess.Device, sess.Account)
}

// writeIssuedBinding mints the per-vault token for a binding and returns it.
//
// `device` is the device that asked for it, and it is recorded on the token so
// revoking that device also ends its access to every shared vault it joined
// (myne-md/myne#911 task 9). A device revocation is a registry change, and the
// token names its device, so no separate sweep is needed: the session check asks
// the registry on every request.
//
// `account` is the SCRAM account that device authenticated as, and it is recorded
// beside it because the registry is keyed by account: without it the revocation
// check has a device it cannot look up (myne-md/myne#911 follow-up).
func (h *Handler) writeIssuedBinding(w http.ResponseWriter, person membership.PersonID, vault membership.VaultID, role membership.Role, device ids.DeviceID, account ids.AccountNumberHash) {
	token, err := h.memberTks.Issue(person, vault, device, account)
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
