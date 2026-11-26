// SPDX-License-Identifier: AGPL-3.0-only

package membership

import (
	"errors"
	"sort"
)

// PersistedBinding is a Binding in a shape that survives a JSON round trip.
// The fixed-size ids travel as byte slices because `[16]byte` marshals as an
// array of numbers, which is neither readable nor stable to diff.
type PersistedBinding struct {
	Person []byte `json:"person"`
	Vault  []byte `json:"vault"`
	Role   uint8  `json:"role"`
}

// ErrBadPersistedRow is returned when a persisted row cannot describe a binding:
// a wrong-length id or a role this version does not know. It fails CLOSED — the
// caller refuses to start rather than dropping the row, because a dropped
// binding is a member silently losing access to a vault.
var ErrBadPersistedRow = errors.New("membership: persisted row is not a valid binding")

// SetOnChange installs the persistence hook. It is called on every mutation that
// changes what a restart must reproduce, and it must be cheap and lock-free: it
// runs while this table's lock is held (the hook is the persistence coordinator's
// dirty flag, not a writer). Call it once, before serving.
func (t *Table) SetOnChange(fn func()) {
	t.mu.Lock()
	t.onChange = fn
	t.mu.Unlock()
}

func (t *Table) changed() {
	if t.onChange != nil {
		t.onChange()
	}
}

// Snapshot returns every binding, sorted, so the same state always serializes to
// the same bytes.
func (t *Table) Snapshot() []PersistedBinding {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]PersistedBinding, 0, len(t.byVault))
	for _, byPerson := range t.byVault {
		for _, b := range byPerson {
			out = append(out, PersistedBinding{Person: b.Person[:], Vault: b.Vault[:], Role: uint8(b.Role)})
		}
	}
	sortPersisted(out)
	return out
}

// Load replaces the table's contents with the persisted rows. It is used at boot,
// before serving and before any hook is installed, and it validates rather than
// trusting: a row this version cannot interpret fails the load.
//
// The swap is atomic from a reader's point of view (built off to the side, then
// assigned under the write lock), so a load can never publish a half-built table.
func (t *Table) Load(rows []PersistedBinding) error {
	byVault := make(map[VaultID]map[PersonID]Binding, len(rows))
	byPerson := make(map[PersonID]map[VaultID]Binding, len(rows))
	for _, r := range rows {
		if len(r.Person) != len(PersonID{}) || len(r.Vault) != len(VaultID{}) {
			return ErrBadPersistedRow
		}
		if Role(r.Role) != RoleOwner && Role(r.Role) != RoleMember {
			return ErrBadPersistedRow
		}
		var person PersonID
		copy(person[:], r.Person)
		var vault VaultID
		copy(vault[:], r.Vault)
		b := Binding{Person: person, Vault: vault, Role: Role(r.Role)}
		if byVault[vault] == nil {
			byVault[vault] = make(map[PersonID]Binding)
		}
		if byPerson[person] == nil {
			byPerson[person] = make(map[VaultID]Binding)
		}
		// Last row wins for a duplicated pair, which is what a re-bind would have
		// produced anyway.
		byVault[vault][person] = b
		byPerson[person][vault] = b
	}
	t.mu.Lock()
	t.byVault, t.byPerson = byVault, byPerson
	t.mu.Unlock()
	return nil
}

func sortPersisted(rows []PersistedBinding) {
	sort.Slice(rows, func(i, j int) bool {
		if string(rows[i].Vault) != string(rows[j].Vault) {
			return string(rows[i].Vault) < string(rows[j].Vault)
		}
		return string(rows[i].Person) < string(rows[j].Person)
	})
}
