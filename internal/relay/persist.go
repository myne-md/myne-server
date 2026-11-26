// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"errors"
	"sort"

	"github.com/myne-md/myne-server/internal/membership"
)

// PersistedInvite is one invite in a JSON-safe shape. The payload travels with
// it: an unclaimed invite's sealed payload exists nowhere else, so a restart that
// dropped it would strand the invite (and it is the owner, not the server, who
// would have to notice and re-issue it).
type PersistedInvite struct {
	ID        []byte `json:"id"`
	Recipient []byte `json:"recipient"`
	Vault     []byte `json:"vault"`
	Payload   []byte `json:"payload"`
	Claimed   bool   `json:"claimed"`
}

// ErrBadPersistedInvite is returned for a row whose ids are the wrong width.
// Fails closed: a dropped invite is a member who cannot join the vault.
var ErrBadPersistedInvite = errors.New("relay: persisted invite row is not a valid invite")

const idLen = 16

// SetOnChange installs the persistence hook (see Table.SetOnChange in package
// membership for the contract). Call once, before serving.
func (s *Store) SetOnChange(fn func()) {
	s.mu.Lock()
	s.onChange = fn
	s.mu.Unlock()
}

func (s *Store) changed() {
	if s.onChange != nil {
		s.onChange()
	}
}

// Snapshot returns every invite, sorted by id, payloads included.
func (s *Store) Snapshot() []PersistedInvite {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PersistedInvite, 0, len(s.byID))
	for _, inv := range s.byID {
		out = append(out, PersistedInvite{
			ID:        inv.ID[:],
			Recipient: inv.Recipient[:],
			Vault:     inv.Vault[:],
			Payload:   inv.Payload,
			Claimed:   inv.Claimed,
		})
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i].ID) < string(out[j].ID) })
	return out
}

// Load replaces the invite table's contents from the persisted rows.
func (s *Store) Load(rows []PersistedInvite) error {
	byID := make(map[InviteID]Invite, len(rows))
	for _, r := range rows {
		if len(r.ID) != idLen || len(r.Recipient) != idLen || len(r.Vault) != idLen {
			return ErrBadPersistedInvite
		}
		var id InviteID
		copy(id[:], r.ID)
		var recipient membership.PersonID
		copy(recipient[:], r.Recipient)
		var vault membership.VaultID
		copy(vault[:], r.Vault)
		payload := make([]byte, len(r.Payload))
		copy(payload, r.Payload)
		byID[id] = Invite{ID: id, Recipient: recipient, Vault: vault, Payload: payload, Claimed: r.Claimed}
	}
	s.mu.Lock()
	s.byID = byID
	s.mu.Unlock()
	return nil
}
