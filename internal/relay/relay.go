// SPDX-License-Identifier: AGPL-3.0

// Package relay is the sealed-invite postbox (myne-md/myne#711,
// decisions/protocol/0599). The owner's authenticated session posts an invite
// addressed to a recipient's person account; the server stores it opaquely and
// releases it to that account on claim, then marks it claimed.
//
// The server is BLIND here in the strict sense: the outer routing frame is
// exactly three fields, the recipient person id, the vault id and the sealed
// payload. No fingerprint, no public half and no group key ever reaches this
// package. The owner of a vault therefore cannot learn a member's fingerprint
// from the relay, and the server cannot read one, because the fields that would
// carry it were moved INSIDE the sealed payload when the frame was reduced
// (decisions/protocol/0599, Grill 4 Q10).
//
// An invite is a postbox slot, not a queue: claiming it consumes it, so a
// claimed invite is not re-claimable.
package relay

import (
	"crypto/rand"
	"errors"
	"sort"
	"sync"

	"github.com/myne-md/myne-server/internal/membership"
)

// InviteID is a server-generated opaque invite id (16 bytes, hex on the wire).
type InviteID [16]byte

// Invite is one stored invite. Payload is opaque sealed bytes; the server never
// parses, interprets or reorders them.
type Invite struct {
	ID        InviteID
	Recipient membership.PersonID
	Vault     membership.VaultID
	Payload   []byte
	Claimed   bool
}

// Meta is the list projection of an invite: everything a recipient may know
// before claiming, and deliberately NOT the payload (the claim is what releases
// it, so a list cannot be used to drain a slot).
type Meta struct {
	ID      InviteID
	Vault   membership.VaultID
	Claimed bool
}

// VaultMeta is the OWNER-side projection of an invite: what a vault's owner may
// see about the invitations it sent (myne-md/myne#711). It adds the recipient
// person id, which the owner supplied when posting, so an owner can render
// claimed-versus-pending without the server releasing any payload. It is still
// not a fingerprint or a public half: those live inside the sealed payload.
type VaultMeta struct {
	ID        InviteID
	Recipient membership.PersonID
	Claimed   bool
}

// Store errors. ErrNotFound is returned both for an unknown id and for an id
// addressed to a DIFFERENT person, so the caller cannot enumerate another
// person's invites or confirm that one exists.
var (
	ErrNotFound = errors.New("relay: invite not found")
	ErrClaimed  = errors.New("relay: invite already claimed")
)

// Store is the in-memory invite table. Like the auth registry it holds no key
// material and no content it can read; persistence is a separate concern (the
// same residual the membership table carries).
type Store struct {
	mu   sync.Mutex
	byID map[InviteID]Invite
}

// NewStore returns an empty relay store.
func NewStore() *Store {
	return &Store{byID: make(map[InviteID]Invite)}
}

// Put stores a sealed invite addressed to recipient for vault and returns its
// generated id. The payload is copied in, never aliased.
func (s *Store) Put(recipient membership.PersonID, vault membership.VaultID, payload []byte) (InviteID, error) {
	var id InviteID
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	buf := make([]byte, len(payload))
	copy(buf, payload)
	s.mu.Lock()
	s.byID[id] = Invite{ID: id, Recipient: recipient, Vault: vault, Payload: buf}
	s.mu.Unlock()
	return id, nil
}

// List returns the recipient's invites in a deterministic order (id ascending),
// without payloads. Claimed invites are included with Claimed set, so a client
// can show what it already accepted rather than watching a slot vanish.
func (s *Store) List(recipient membership.PersonID) []Meta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Meta, 0)
	for _, inv := range s.byID {
		if inv.Recipient == recipient {
			out = append(out, Meta{ID: inv.ID, Vault: inv.Vault, Claimed: inv.Claimed})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return string(out[i].ID[:]) < string(out[j].ID[:])
	})
	return out
}

// ListByVault returns a vault's invites in a deterministic order (id
// ascending), without payloads. It is the OWNER-side view (myne-md/myne#711):
// an owner renders claimed-versus-pending for the invitations it sent, while
// the server still releases no payload and learns no fingerprint.
func (s *Store) ListByVault(vault membership.VaultID) []VaultMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]VaultMeta, 0)
	for _, inv := range s.byID {
		if inv.Vault == vault {
			out = append(out, VaultMeta{ID: inv.ID, Recipient: inv.Recipient, Claimed: inv.Claimed})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return string(out[i].ID[:]) < string(out[j].ID[:])
	})
	return out
}

// Claim releases an invite addressed to the caller and consumes it. A wrong
// recipient is ErrNotFound (not a distinct refusal, so no enumeration signal);
// a second claim by the recipient is ErrClaimed.
func (s *Store) Claim(recipient membership.PersonID, id InviteID) (Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.byID[id]
	if !ok || inv.Recipient != recipient {
		return Invite{}, ErrNotFound
	}
	if inv.Claimed {
		return Invite{}, ErrClaimed
	}
	inv.Claimed = true
	s.byID[id] = inv
	return inv, nil
}
