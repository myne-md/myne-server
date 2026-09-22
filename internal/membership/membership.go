// SPDX-License-Identifier: AGPL-3.0

// Package membership is the person-to-vault access model (myne-md/myne#711,
// decisions/protocol/0599). A person account is independent of any vault; a
// vault keeps its `account_number_hash` as its public id, and access to it is an
// explicit binding here. The binding is what the server authorises a per-vault
// token against, and it is an AVAILABILITY control only: the server is blind, so
// it never reads the vault's content and never verifies the owner's signature
// over a roster.
//
// The server therefore learns the pseudonymous person-to-vault mapping (the
// collaboration social graph), which is the exposure `docs/threat-model.md` 7(4)
// already accepts (decisions 0459). It reads no roster plaintext, no fingerprint
// and no name.
package membership

import (
	"errors"
	"sync"

	"github.com/myne-md/myne-server/internal/ids"
)

// PersonID is the person's account id (the client's `person_id_hash`, a pure
// function of the recovery phrase). It is pseudonymous: the server cannot invert
// it to a person.
type PersonID [16]byte

// VaultID is a vault's public id: the vault `account_number_hash`.
type VaultID = ids.AccountNumberHash

// Role is a binding's standing in a vault.
type Role uint8

const (
	// RoleOwner is the vault's single owner (the client's `root_key` holder).
	RoleOwner Role = iota
	// RoleMember is any non-owner member.
	RoleMember
)

// Binding is one person's access to one vault.
type Binding struct {
	Person PersonID
	Vault  VaultID
	Role   Role
}

// Table errors.
var (
	ErrOwnerExists   = errors.New("membership: vault already has an owner")
	ErrOwnerNotFound = errors.New("membership: vault has no such owner binding")
	ErrAlreadyBound  = errors.New("membership: person already bound to vault")
	ErrNotBound      = errors.New("membership: person not bound to vault")
)

// Table is the in-memory person↔vault membership. It is the server-side
// authority for token scoping; it is deliberately NOT a cryptographic roster.
type Table struct {
	mu       sync.RWMutex
	byVault  map[VaultID]map[PersonID]Binding
	byPerson map[PersonID]map[VaultID]Binding
}

// New returns an empty membership table.
func New() *Table {
	return &Table{
		byVault:  make(map[VaultID]map[PersonID]Binding),
		byPerson: make(map[PersonID]map[VaultID]Binding),
	}
}

func (t *Table) bind(b Binding) {
	if t.byVault[b.Vault] == nil {
		t.byVault[b.Vault] = make(map[PersonID]Binding)
	}
	if t.byPerson[b.Person] == nil {
		t.byPerson[b.Person] = make(map[VaultID]Binding)
	}
	t.byVault[b.Vault][b.Person] = b
	t.byPerson[b.Person][b.Vault] = b
}

// BindOwner records the vault's single owner. The vault has exactly one owner
// (the client's singleton-owner rule), so a second owner binding is refused;
// re-binding the SAME person as owner is idempotent.
func (t *Table) BindOwner(vault VaultID, person PersonID) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing, ok := t.byVault[vault]; ok {
		for _, b := range existing {
			if b.Role == RoleOwner && b.Person != person {
				return ErrOwnerExists
			}
		}
	}
	if t.byVault[vault] != nil {
		if _, ok := t.byVault[vault][person]; ok {
			return nil // already the owner
		}
	}
	t.bind(Binding{Person: person, Vault: vault, Role: RoleOwner})
	return nil
}

// BindMember records a member's access. The binding is created by the owner at
// invite acceptance; re-binding an existing member is refused (remove first).
func (t *Table) BindMember(vault VaultID, person PersonID) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.byVault[vault][person]; ok {
		return ErrAlreadyBound
	}
	t.bind(Binding{Person: person, Vault: vault, Role: RoleMember})
	return nil
}

// Remove deletes a person's binding from a vault. Removing the owner is refused:
// the owner is the vault's administrator and leaves only by deleting the vault.
func (t *Table) Remove(vault VaultID, person PersonID) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.byVault[vault][person]
	if !ok {
		return ErrNotBound
	}
	if b.Role == RoleOwner {
		return ErrOwnerNotFound
	}
	delete(t.byVault[vault], person)
	delete(t.byPerson[person], vault)
	return nil
}

// Role returns a person's role in a vault, or ok=false when unbound.
func (t *Table) Role(vault VaultID, person PersonID) (Role, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	b, ok := t.byVault[vault][person]
	if !ok {
		return RoleMember, false
	}
	return b.Role, true
}

// OwnerOf returns the vault's owner binding, or ok=false when none is recorded.
func (t *Table) OwnerOf(vault VaultID) (Binding, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, b := range t.byVault[vault] {
		if b.Role == RoleOwner {
			return b, true
		}
	}
	return Binding{}, false
}

// Members returns the vault's bindings, owner first then members sorted by id.
func (t *Table) Members(vault VaultID) []Binding {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Binding, 0, len(t.byVault[vault]))
	for _, b := range t.byVault[vault] {
		out = append(out, b)
	}
	sortBindings(out)
	return out
}

// Vaults returns the vaults a person is bound to, sorted by id.
func (t *Table) Vaults(person PersonID) []Binding {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Binding, 0, len(t.byPerson[person]))
	for _, b := range t.byPerson[person] {
		out = append(out, b)
	}
	sortBindings(out)
	return out
}

func sortBindings(bs []Binding) {
	// Owner first, then by vault then person, so the order is total and stable.
	for i := 1; i < len(bs); i++ {
		for j := i; j > 0 && less(bs[j], bs[j-1]); j-- {
			bs[j], bs[j-1] = bs[j-1], bs[j]
		}
	}
}

func less(a, b Binding) bool {
	if a.Role != b.Role {
		return a.Role == RoleOwner // owner first
	}
	if a.Vault != b.Vault {
		return string(a.Vault[:]) < string(b.Vault[:])
	}
	return string(a.Person[:]) < string(b.Person[:])
}
