// SPDX-License-Identifier: AGPL-3.0-only
// Vault discovery for a person account (myne-md/myne#911 task 7).
//
// The client's second device has to learn WHICH vaults this person is bound to
// before it can sync any of them: one person token replaces the per-vault tokens
// the old model handed out one vault at a time. The answer is a read of the
// two-way membership index this server already keeps, which until now had no
// production caller (`membership.Table.Vaults`).
//
// What this route does NOT do is authorize anything. It lists bindings; syncing
// against one of them is a separate request that the sync surface authorizes
// again, per vault, through the same table. A cached or stale discovery answer
// therefore cannot grant access to a vault the person has since been removed
// from.
package authapi

import (
	"encoding/hex"
	"net/http"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/membership"
)

// vaultBindingWire is one row of the discovery answer.
//
// `role` is `"owner"` or `"member"`, the same two words §3.1a uses. It is here
// because the client's vault list shows the difference, and it costs the server
// nothing: it is already the column the binding is stored under.
type vaultBindingWire struct {
	AccountHashHex string `json:"account_hash_hex"`
	Role           string `json:"role"`
}

// handleDiscoverVaults answers `GET /b2b/vaults` for the calling account.
//
// The caller is any authenticated session, and the answer is whatever bindings
// that ACCOUNT holds. For a person that is the vault list; for a vault's own
// device token it is normally empty, which is the honest answer rather than an
// error: the route asks "what is this account bound to", and a vault is not
// bound to anything.
//
// Ordered owner-first then by vault id, because `membership.Vaults` sorts that
// way and a client that renders in received order would otherwise shuffle its
// vault list between polls.
func (h *Handler) handleDiscoverVaults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	if h.members == nil {
		// Membership is not wired in this deployment: report the absence rather
		// than an empty list, because an empty list is a claim about the account.
		writeErr(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
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
	bindings := h.members.Vaults(personFromSession(sess))
	out := make([]vaultBindingWire, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, vaultBindingWire{
			AccountHashHex: hex.EncodeToString(b.Vault[:]),
			Role:           roleString(b.Role),
		})
	}
	writeJSON(w, map[string][]vaultBindingWire{"vaults": out})
}

// roleString is the wire spelling of a binding's role: the two words §3.1a uses.
func roleString(role membership.Role) string {
	if role == membership.RoleOwner {
		return "owner"
	}
	return "member"
}
