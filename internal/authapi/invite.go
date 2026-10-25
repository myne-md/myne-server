// SPDX-License-Identifier: AGPL-3.0

package authapi

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
	"github.com/myne-md/myne-server/internal/relay"
)

// This file is the sealed-invite relay surface (myne-md/myne#711,
// decisions/protocol/0599), the three routes frozen by that decision:
//
//	POST /b2b/invites                      owner posts a sealed invite
//	GET  /b2b/invites                      recipient lists invites addressed to it
//	POST /b2b/invites/{invite_id}/claim    recipient claims one, binding the vault
//	DELETE /b2b/invites/{invite_id}        recipient declines one, which drops its payload
//
// The outer routing frame is the recipient person id, the vault id and the
// opaque sealed payload. Because the relay is addressed by person id, the
// recipient must already hold a person account (registered at identity setup),
// which is exactly why the identity-only path exists.
//
// Authorization is split by direction, which is the point: the OWNER posts with
// a per-vault membership token (so only that vault's owner can address an
// invite for it), and the RECIPIENT lists/claims with their own person session
// (so no one else can read or consume their postbox).

// maxInviteBytes bounds a sealed invite payload. The frame is small (public
// halves and a wrapped group key), so this is generous; without it an
// authenticated owner could stream a large body through the relay and make the
// server hold it.
const maxInviteBytes = 64 * 1024

func personFromSession(sess auth.Session) membership.PersonID {
	return membership.PersonID(sess.Account)
}

type createInviteReq struct {
	RecipientPersonIDHex string `json:"recipient_person_id_hex"`
	PayloadB64           string `json:"payload_b64"`
}

// createInviteResp carries ONLY the outer routing frame. The server echoes the
// recipient and vault ids because they are already public to the caller (it
// supplied them, or holds them in the token); the payload is not echoed.
type createInviteResp struct {
	InviteIDHex          string `json:"invite_id_hex"`
	VaultAccountHashHex  string `json:"vault_account_hash_hex"`
	RecipientPersonIDHex string `json:"recipient_person_id_hex"`
}

func (h *Handler) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	// Only the vault's owner may address an invite for it: the per-vault token
	// carries the vault, so the route needs no vault in its path.
	b, err := h.memberTks.Resolve(tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	if b.Role != membership.RoleOwner {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var req createInviteReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInviteBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	recipient, ok := parsePersonID(req.RecipientPersonIDHex)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	payload, err := base64.StdEncoding.DecodeString(req.PayloadB64)
	if err != nil || len(payload) == 0 || len(payload) > maxInviteBytes {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	id, err := h.relay.Put(recipient, b.Vault, payload)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, createInviteResp{
		InviteIDHex:          hex.EncodeToString(id[:]),
		VaultAccountHashHex:  hex.EncodeToString(b.Vault[:]),
		RecipientPersonIDHex: hex.EncodeToString(recipient[:]),
	})
}

type inviteWire struct {
	InviteIDHex         string `json:"invite_id_hex"`
	VaultAccountHashHex string `json:"vault_account_hash_hex"`
	Claimed             bool   `json:"claimed"`
}

func (h *Handler) handleListInvites(w http.ResponseWriter, r *http.Request) {
	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	sess, err := h.tokens.AuthenticateSession(tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, auth.FailureCode(err))
		return
	}
	metas := h.relay.List(personFromSession(sess))
	out := make([]inviteWire, 0, len(metas))
	for _, m := range metas {
		out = append(out, inviteWire{
			InviteIDHex:         hex.EncodeToString(m.ID[:]),
			VaultAccountHashHex: hex.EncodeToString(m.Vault[:]),
			Claimed:             m.Claimed,
		})
	}
	writeJSON(w, map[string][]inviteWire{"invites": out})
}

type vaultInviteWire struct {
	InviteIDHex          string `json:"invite_id_hex"`
	RecipientPersonIDHex string `json:"recipient_person_id_hex"`
	Claimed              bool   `json:"claimed"`
	Declined             bool   `json:"declined"`
}

// handleListVaultInvites lists the invitations a vault's OWNER has sent, with
// the claimed flag, so the owner's roster can show claimed-versus-pending
// (myne-md/myne#711). It is the vault-side twin of handleListInvites: the
// recipient sees what is addressed to it, the owner sees what it sent.
//
// Authorization is the owner's per-vault membership token; a member token is
// refused 403. The projection carries the recipient person id (the owner
// supplied it) and never the payload, so the server still releases nothing and
// reads no fingerprint.
func (h *Handler) handleListVaultInvites(w http.ResponseWriter, r *http.Request) {
	vault, ok := ids.ParseAccountNumberHash(r.PathValue("account_hash"))
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
	metas := h.relay.ListByVault(vault)
	out := make([]vaultInviteWire, 0, len(metas))
	for _, m := range metas {
		out = append(out, vaultInviteWire{
			InviteIDHex:          hex.EncodeToString(m.ID[:]),
			RecipientPersonIDHex: hex.EncodeToString(m.Recipient[:]),
			Claimed:              m.Claimed,
			Declined:             m.Declined,
		})
	}
	writeJSON(w, map[string][]vaultInviteWire{"invites": out})
}

type claimInviteResp struct {
	PayloadB64          string `json:"payload_b64"`
	VaultAccountHashHex string `json:"vault_account_hash_hex"`
	// TokenHex is the claiming person's per-vault token, minted by the claim.
	// This is the member-facing token issuance path ("member at acceptance");
	// the owner-side bind route is the other.
	TokenHex string `json:"token_hex"`
}

func (h *Handler) handleClaimInvite(w http.ResponseWriter, r *http.Request) {
	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	sess, err := h.tokens.AuthenticateSession(tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, auth.FailureCode(err))
		return
	}
	inviteID, ok := parseInviteID(r.PathValue("invite_id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	person := personFromSession(sess)
	inv, err := h.relay.Claim(person, inviteID)
	if err != nil {
		// A re-claim by the invite's own recipient is idempotent ONLY while that
		// person's binding to the vault still stands (member-devices). The relay
		// retains the invite, so without this check a member the owner removed
		// could re-claim the stored invite and re-acquire access. A removed
		// recipient therefore gets the same 404, which also keeps the route from
		// being an oracle. Unknown id and wrong recipient are the same 404 too: a
		// different account must not be able to confirm that an invite exists.
		if !errors.Is(err, relay.ErrClaimed) {
			writeErr(w, http.StatusNotFound, "not_found")
			return
		}
		if _, bound := h.members.Role(inv.Vault, person); !bound {
			writeErr(w, http.StatusNotFound, "not_found")
			return
		}
	}
	// Acceptance binds the member. On a first claim the binding is absent and this
	// creates it; on an allowed re-claim it already exists, so ErrAlreadyBound is
	// tolerated and the token below is what the claim is for.
	if err := h.members.BindMember(inv.Vault, person); err != nil &&
		!errors.Is(err, membership.ErrAlreadyBound) {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	// The claiming device is recorded on the token, so one device revocation
	// retires the shared vaults it joined as well (myne-md/myne#911 task 9). Its
	// account travels with it: the device registry is keyed by account, and this is
	// the account the revocation check must ask about (myne-md/myne#911 follow-up).
	token, err := h.memberTks.Issue(person, inv.Vault, sess.Device, sess.Account)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, claimInviteResp{
		PayloadB64:          base64.StdEncoding.EncodeToString(inv.Payload),
		VaultAccountHashHex: hex.EncodeToString(inv.Vault[:]),
		TokenHex:            hex.EncodeToString(token),
	})
}

// parseInviteID decodes a 16-byte invite id from lowercase hex.
func parseInviteID(s string) (relay.InviteID, bool) {
	var id relay.InviteID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, false
	}
	copy(id[:], b)
	return id, true
}

// handleDeclineInvite is the recipient's refusal of an invitation
// (myne-md/myne#911 follow-up): DELETE /b2b/invites/{invite_id} under the
// recipient's own person session.
//
// It is a REAL server-side deletion of the sealed payload, not a client-side
// hide. Without it the only two things an invitee could do were "accept" and
// "wait", and the owner's list could not tell somebody who declined from
// somebody who had not opened the app yet. The slot keeps a payload-free
// tombstone so the owner's §3.1a view can report "declined"; the claim route
// then answers the same 404 an unknown id gives.
//
// Authorization mirrors the claim: the caller must be the invite's own
// recipient. A wrong account, an unknown id and an already-declined slot are all
// the same 404, so the route cannot be used to enumerate another person's
// invitations. An already-CLAIMED invite is a conflict rather than a delete: the
// caller is already a member of that vault, and declining an invitation it
// accepted makes no sense.
func (h *Handler) handleDeclineInvite(w http.ResponseWriter, r *http.Request) {
	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	sess, err := h.tokens.AuthenticateSession(tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, auth.FailureCode(err))
		return
	}
	inviteID, ok := parseInviteID(r.PathValue("invite_id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	inv, err := h.relay.Decline(personFromSession(sess), inviteID)
	if err != nil {
		if errors.Is(err, relay.ErrClaimed) {
			writeErr(w, http.StatusConflict, "already_claimed")
			return
		}
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, map[string]string{
		"invite_id_hex":          hex.EncodeToString(inv.ID[:]),
		"vault_account_hash_hex": hex.EncodeToString(inv.Vault[:]),
	})
}
