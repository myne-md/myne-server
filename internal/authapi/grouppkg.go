// SPDX-License-Identifier: AGPL-3.0-only

package authapi

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
)

// MaxGroupPackageBytes bounds one opaque rotation package. An owner-signed
// group package is a small canonical-JSON payload plus a double signature, far
// under this; the cap only stops an authenticated owner from streaming a giant
// blob into the relay.
const MaxGroupPackageBytes = 64 * 1024

type putGroupPackageReq struct {
	// Epoch is cleartext retention metadata: the group-key epoch the package is
	// for. The server reads only this and the routing ids; PackageB64 is opaque.
	Epoch      uint64 `json:"epoch"`
	PackageB64 string `json:"package_b64"`
}

type getGroupPackageResp struct {
	Epoch      uint64 `json:"epoch"`
	PackageB64 string `json:"package_b64"`
}

// handlePutGroupPackage — the owner's write of one member's rotation package at
// `PUT /b2b/vaults/{account_hash}/group-packages/{person_id}`. Authorized by the
// owner's per-vault membership token; the token's vault must be this vault and
// its role must be owner, exactly like the invite create route. The package
// bytes are stored verbatim and never parsed.
func (h *Handler) handlePutGroupPackage(w http.ResponseWriter, r *http.Request) {
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
	if b.Role != membership.RoleOwner || b.Vault != vault {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var req putGroupPackageReq
	if err := json.NewDecoder(io.LimitReader(r.Body, MaxGroupPackageBytes*2)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	pkg, err := base64.StdEncoding.DecodeString(req.PackageB64)
	if err != nil || len(pkg) == 0 || len(pkg) > MaxGroupPackageBytes {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	h.groupPkgs.Put(vault, person, req.Epoch, pkg)
	writeJSON(w, map[string]bool{"ok": true})
}

// handleGetGroupPackage — a member's read of its OWN rotation package at
// `GET /b2b/vaults/{account_hash}/group-packages/{person_id}`. Authorized by the
// recipient's person session plus its membership binding to this vault. The path
// `person_id` must be the caller's own; a differing one is reported as
// not-found so the route cannot address another member's package, and a
// non-member gets the same answer behind the binding check.
func (h *Handler) handleGetGroupPackage(w http.ResponseWriter, r *http.Request) {
	vault, person, ok := h.profileAuth(w, r)
	if !ok {
		return
	}
	// The path person must be the session's own person. A mismatch is the same
	// 404 as an absent package (no enumeration signal, mirrors profileAuth's
	// derived-id refusal but with a not-found rather than forbidden answer).
	if path, ok := parsePersonID(r.PathValue("person_id")); !ok || path != person {
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	rec, err := h.groupPkgs.Get(vault, person)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, getGroupPackageResp{
		Epoch:      rec.Epoch,
		PackageB64: base64.StdEncoding.EncodeToString(rec.Package),
	})
}
