// SPDX-License-Identifier: AGPL-3.0-only

package grouppkg

import (
	"errors"
	"sort"

	"github.com/myne-md/myne-server/internal/membership"
)

// PersistedPackage is one stored rotation package in a JSON-safe shape. It is the
// newest package for its (vault, person): Put keeps the highest epoch, so a
// restart that lost it would leave a member unable to unwrap the current epoch
// until the owner re-issued one.
type PersistedPackage struct {
	Vault   []byte `json:"vault"`
	Person  []byte `json:"person"`
	Epoch   uint64 `json:"epoch"`
	Package []byte `json:"package"`
}

// ErrBadPersistedPackage is returned for a row whose ids are the wrong width.
var ErrBadPersistedPackage = errors.New("grouppkg: persisted row is not a valid package")

const idLen = 16

// SetOnChange installs the persistence hook. Call once, before serving.
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

// Snapshot returns every package, sorted by (vault, person).
func (s *Store) Snapshot() []PersistedPackage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PersistedPackage, 0, len(s.byKey))
	for k, rec := range s.byKey {
		out = append(out, PersistedPackage{
			Vault:   k.vault[:],
			Person:  k.person[:],
			Epoch:   rec.Epoch,
			Package: rec.Package,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if string(out[i].Vault) != string(out[j].Vault) {
			return string(out[i].Vault) < string(out[j].Vault)
		}
		return string(out[i].Person) < string(out[j].Person)
	})
	return out
}

// Load replaces the store's contents from the persisted rows.
func (s *Store) Load(rows []PersistedPackage) error {
	next := make(map[key]Record, len(rows))
	for _, r := range rows {
		if len(r.Vault) != idLen || len(r.Person) != idLen {
			return ErrBadPersistedPackage
		}
		var vault membership.VaultID
		copy(vault[:], r.Vault)
		var person membership.PersonID
		copy(person[:], r.Person)
		buf := make([]byte, len(r.Package))
		copy(buf, r.Package)
		next[key{vault: vault, person: person}] = Record{Vault: vault, Person: person, Epoch: r.Epoch, Package: buf}
	}
	s.mu.Lock()
	s.byKey = next
	s.mu.Unlock()
	return nil
}
