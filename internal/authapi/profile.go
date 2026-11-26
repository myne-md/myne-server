// SPDX-License-Identifier: AGPL-3.0-only

package authapi

import (
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
	"github.com/myne-md/myne-server/internal/profiles"
)

// This file is the person-private AI profile plane (myne-md/myne#711 task 16,
// protocol.md §9.28). A profile is one sealed `MYY5` blob per (vault, person),
// in a vault-scoped namespace that is SEPARATE from the shared group manifest:
// the server stores it opaquely and reads none of it, and it never appears in
// the manifest peers sync.
//
// Authorization is the PERSON's own account session (not a vault device token),
// plus a membership binding to the vault: only a person who belongs to the vault
// may read or write a profile in it. The server records the writing person so
// member removal can schedule that person's profile for deletion.
//
// Routes (decisions/protocol/0599 route family):
//
//	PUT /b2b/vaults/{account_hash}/profiles/{profile_id}
//	GET /b2b/vaults/{account_hash}/profiles/{profile_id}

// maxProfileBytes bounds a sealed profile body. `MAX_PERSON_PROFILE_PLAINTEXT_LEN`
// is 16 MiB; this leaves room for the header and AEAD tag.
const maxProfileBytes = (16 * 1024 * 1024) + 128

// DefaultProfileDeleteGrace is how long a removed member's profiles survive
// before reclamation. The value is a retention POLICY input
// (the operations repository#48), so it is a server setting rather than a protocol
// constant; this is the shipped default.
const DefaultProfileDeleteGrace = 30 * 24 * time.Hour

// Profiles returns the person-private profile store, for tests and for the
// removal path's scheduled cleanup.
func (h *Handler) Profiles() *profiles.Store { return h.profs }

// WithProfileDeleteGrace overrides the removal retention grace (tests use a
// short one). A non-positive value restores the default.
func (h *Handler) WithProfileDeleteGrace(d time.Duration) *Handler {
	h.profileDeleteGrace = d
	return h
}

// scheduleProfileDeletion records that the removed person's profiles for this
// vault are to be reclaimed after the retention grace. It makes no recall
// claim: anything the person already holds is not erasable.
func (h *Handler) scheduleProfileDeletion(vault ids.AccountNumberHash, person membership.PersonID) {
	grace := h.profileDeleteGrace
	if grace <= 0 {
		grace = DefaultProfileDeleteGrace
	}
	h.profs.ScheduleDeletionByPerson(vault, person, time.Now().Add(grace))
}

func parseProfileID(s string) (profiles.ProfileID, bool) {
	var id profiles.ProfileID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, false
	}
	copy(id[:], b)
	return id, true
}

// ownProfile parses the path profile id and refuses one that is not the
// caller's own. The id is a pure function of `(person, vault)`, so the server
// recomputes it and compares: a member may never address another member's
// profile, which the sealed-blob opacity alone does NOT prevent (a peer's
// person_id_hash is visible in the roster, so the id is derivable by anyone
// bound to the vault). A mismatch is the same `403` a non-member gets, so the
// route does not confirm that some other profile exists.
func (h *Handler) ownProfile(
	w http.ResponseWriter,
	raw string,
	vault ids.AccountNumberHash,
	person membership.PersonID,
) (profiles.ProfileID, bool) {
	profile, ok := parseProfileID(raw)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return profiles.ProfileID{}, false
	}
	if profile != profiles.DeriveProfileID(vault, person) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return profiles.ProfileID{}, false
	}
	return profile, true
}

// profileAuth resolves the vault and the calling person, refusing an unknown
// bearer (401) and a person who is not bound to the vault (403).
func (h *Handler) profileAuth(w http.ResponseWriter, r *http.Request) (ids.AccountNumberHash, membership.PersonID, bool) {
	vault, ok := ids.ParseAccountNumberHash(r.PathValue("account_hash"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return ids.AccountNumberHash{}, membership.PersonID{}, false
	}
	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return ids.AccountNumberHash{}, membership.PersonID{}, false
	}
	sess, err := h.tokens.AuthenticateSession(tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return ids.AccountNumberHash{}, membership.PersonID{}, false
	}
	person := membership.PersonID(sess.Account)
	if _, bound := h.members.Role(vault, person); !bound {
		writeErr(w, http.StatusForbidden, "forbidden")
		return ids.AccountNumberHash{}, membership.PersonID{}, false
	}
	return vault, person, true
}

func (h *Handler) handlePutProfile(w http.ResponseWriter, r *http.Request) {
	vault, person, ok := h.profileAuth(w, r)
	if !ok {
		return
	}
	profile, ok := h.ownProfile(w, r.PathValue("profile_id"), vault, person)
	if !ok {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxProfileBytes))
	if err != nil || len(body) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	h.profs.Put(vault, profile, person, body)
	writeJSON(w, map[string]bool{"ok": true})
}

func (h *Handler) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	vault, person, ok := h.profileAuth(w, r)
	if !ok {
		return
	}
	profile, ok := h.ownProfile(w, r.PathValue("profile_id"), vault, person)
	if !ok {
		return
	}
	row, found := h.profs.Get(vault, profile)
	if !found {
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(row.Bytes)
}
