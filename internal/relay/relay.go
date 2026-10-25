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
// An invite is a postbox slot, not a queue: it retains its sealed payload, and
// the Claimed flag records that it has been claimed at least once rather than
// consuming the slot. A re-claim is idempotent only for the invite's OWN
// recipient whose binding to the vault still stands: Claim returns the stored
// invite again (payload included, alongside ErrClaimed) so the caller can check
// that binding and, if it holds, let a member's second device obtain its own
// per-vault token without the owner. A recipient the owner has since removed
// must NOT be able to re-claim the retained invite back into the vault, and
// every other caller still sees the same ErrNotFound an unknown id gives, so the
// rule widens no enumeration signal. Meta, the recipient projection, still
// deliberately excludes the payload: a list cannot be used to drain a slot, and
// the Claimed flag is what the owner's view reads.
//
// Declining is the recipient's own exit and it DESTROYS the slot's payload (see
// Store.Decline): the sender then reads "declined" from a tombstone that holds
// nothing but the three ids and the flag.
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
//
// Declined is the recipient's refusal (myne-md/myne#911 follow-up). It is a real
// delete of the sealed payload rather than a client-side hide: a declined slot
// releases nothing and can never be claimed, and the ROW survives only so the
// owner's view can say "declined" instead of "not accepted yet". The tombstone
// therefore holds no payload and no group key: three ids and one flag.
type Invite struct {
	ID        InviteID
	Recipient membership.PersonID
	Vault     membership.VaultID
	Payload   []byte
	Claimed   bool
	Declined  bool
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
// Declined is the third state that projection can carry.
type VaultMeta struct {
	ID        InviteID
	Recipient membership.PersonID
	Claimed   bool
	Declined  bool
}

// ErrNotFound is returned both for an unknown id and for an id addressed to a
// DIFFERENT person, so the caller cannot enumerate another person's invites or
// confirm that one exists. A re-claim by the invite's own recipient is signalled
// with ErrClaimed instead, which carries the stored invite (see Claim). A
// declined invite answers ErrNotFound like an unknown one: there is no slot left
// to claim.
var (
	ErrNotFound = errors.New("relay: invite not found")
	ErrClaimed  = errors.New("relay: invite already claimed")
)

// Store is the in-memory invite table. Like the auth registry it holds no key
// material and no content it can read; persistence is a separate concern (the
// same residual the membership table carries).
type Store struct {
	mu       sync.Mutex
	byID     map[InviteID]Invite
	onChange func()
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
	s.changed()
	s.mu.Unlock()
	return id, nil
}

// List returns the recipient's invites in a deterministic order (id ascending),
// without payloads. Claimed invites are included with Claimed set, so a client
// can show what it already accepted rather than watching a slot vanish.
// Declined ones are not listed at all: the recipient is the party that refused
// them, so there is nothing left to tell it.
func (s *Store) List(recipient membership.PersonID) []Meta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Meta, 0)
	for _, inv := range s.byID {
		if inv.Recipient == recipient && !inv.Declined {
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
			out = append(out, VaultMeta{
				ID:        inv.ID,
				Recipient: inv.Recipient,
				Claimed:   inv.Claimed,
				Declined:  inv.Declined,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return string(out[i].ID[:]) < string(out[j].ID[:])
	})
	return out
}

// Claim releases an invite addressed to the caller. A wrong recipient or an
// unknown id is ErrNotFound (not a distinct refusal, so no enumeration signal).
// A first claim marks the invite claimed and returns it with a nil error. A
// later claim by the SAME recipient returns the stored invite (payload
// included) TOGETHER WITH ErrClaimed: the value is meaningful on that path. The
// relay holds no membership state, so it cannot itself judge that re-claim: the
// caller checks that the recipient's binding to the vault still stands
// (member-devices), which is what stops a removed member from re-claiming a
// retained invite back into the vault.
func (s *Store) Claim(recipient membership.PersonID, id InviteID) (Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.byID[id]
	if !ok || inv.Recipient != recipient || inv.Declined {
		return Invite{}, ErrNotFound
	}
	if inv.Claimed {
		// Already claimed: hand the stored invite back with the signal, so the
		// caller has the payload and the vault to check the binding against.
		return inv, ErrClaimed
	}
	inv.Claimed = true
	s.byID[id] = inv
	s.changed()
	return inv, nil
}

// Decline is the recipient's refusal of an invite: the sealed payload is DROPPED
// on the spot and the slot can never be claimed, while a payload-free tombstone
// stays so the owner's list can report "declined" rather than "not accepted
// yet". The rule that makes it safe to keep the row is that it keeps nothing
// worth releasing: no payload, no fingerprint, no public half.
//
// Errors mirror Claim, and for the same reason: an unknown id and somebody
// else's id are one ErrNotFound, so declining is not an enumeration oracle. An
// already-claimed invite answers ErrClaimed: that recipient is already a member,
// and the act that ends that is the owner's removal, not a declined invitation.
func (s *Store) Decline(recipient membership.PersonID, id InviteID) (Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.byID[id]
	if !ok || inv.Recipient != recipient {
		return Invite{}, ErrNotFound
	}
	if inv.Claimed {
		return inv, ErrClaimed
	}
	inv.Declined = true
	inv.Payload = nil
	s.byID[id] = inv
	s.changed()
	return inv, nil
}
