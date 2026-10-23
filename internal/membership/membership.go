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
	"bytes"
	"errors"
	"sort"
	"sync"

	"github.com/myne-md/myne-server/internal/ids"
)

// PersonID is the person's account id (the client's `person_id_hash`, a pure
// function of the recovery phrase). It is pseudonymous: the server cannot invert
// it to a person.
type PersonID [16]byte

// VaultID is a vault's public id: the vault `account_number_hash`.
type VaultID = ids.AccountNumberHash

// DeviceID is one device of a person's account.
type DeviceID = ids.DeviceID

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
	// Device is the device the per-vault token was ISSUED to, when the issuing
	// route knows it (myne-md/myne#911 task 9). It is not part of the access
	// decision: it exists so revoking a device also stops the shared vaults that
	// device joined, through one check on the device registry.
	//
	// The zero value means UNATTRIBUTABLE, and it is treated as such rather than
	// guessed at: a token persisted before this field existed cannot be tied to a
	// device, so a device revocation leaves it working rather than revoking
	// somebody else's. Recorded in `design notes/` by the person-account work.
	Device DeviceID
	// Account is the SCRAM account that device is REGISTERED under, i.e. the account
	// its session authenticated as when the token was minted.
	//
	// It exists because `Device` alone is not answerable: the device registry is
	// keyed by account (`auth.Registry.Get(account, device)`), and the account a
	// shared vault's tokens are minted under is not the person who owns the vault.
	// Every pre-B2B vault's owner binding is minted by the VAULT's own device token,
	// whose session account is the vault's account number, while the binding's
	// `Person` is the owner's person id: asking the registry about the person found
	// nothing and answered "revoked" for a live device, so every owner's
	// `vault.meta` write and every rotation delivery was refused `device_revoked`
	// (myne-md/myne#911 follow-up).
	//
	// The zero value means UNATTRIBUTABLE, exactly as it does for `Device`, and for
	// the same reason: a row persisted before this field existed must not be guessed
	// into an account it may not belong to.
	Account ids.AccountNumberHash
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
//
// Persistence: `onChange` is the hook the boot-time persistence coordinator
// installs, so a binding survives a restart. Losing the table would not leak
// anything, but it would silently revoke every member's access until the owner
// re-invited them.
type Table struct {
	mu       sync.RWMutex
	byVault  map[VaultID]map[PersonID]Binding
	byPerson map[PersonID]map[VaultID]Binding
	onChange func()
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
	t.changed()
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
	t.changed()
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
	t.changed()
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

// Persons returns every person that holds at least one binding, sorted by id.
//
// It exists so the operator console can NAME a person account at all: a person
// namespace carries no blobs, so `BlobStore.ListAccounts` never lists one, and an
// erasure the console cannot target is an erasure only the database can perform
// (myne-md/myne#911, account erasure).
func (t *Table) Persons() []PersonID {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]PersonID, 0, len(t.byPerson))
	for p := range t.byPerson {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i][:], out[j][:]) < 0
	})
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
