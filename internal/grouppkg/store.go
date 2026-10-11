// SPDX-License-Identifier: AGPL-3.0

// Package grouppkg is the blind relay for per-member group-rotation packages
// (collab-b2b-sessions task 1, decisions/protocol/0603 + 0607). When an owner
// removes a member, the group key rotates and every REMAINING member is owed one
// owner-signed package wrapping the new group key at the new epoch. The owner
// POSTs each package here; a member fetches its own once its sync cycle observes
// a strictly-greater `vault.meta` epoch, verifies the owner signature against the
// pinned owner public half, and unwraps the new group key.
//
// The server parses NO payload: a record is `{vault, person, epoch, package}`
// where `package` is opaque owner-signed bytes carried verbatim and `epoch` is
// cleartext routing metadata the retention rule needs. The removal excludes the
// removed member, so its row is never a recipient.
//
// Retention is latest-per-recipient: a write at an epoch not greater than the one
// already stored is ignored, so a replayed or stale write cannot regress a
// caught-up recipient. Unlike the invite relay a package is NOT one-shot
// consumed: it must be retrievable until the recipient's next sync catches up,
// which may be days later.
//
// KNOWN BOUND (a residual, not a bug): the store is process-lifetime. The
// days-later retrievability above holds only while THIS process keeps running, so
// a restart between the owner's POST and the recipient's next sync drops the
// package. That is the same posture the invite and profile relays take, and it is
// loud rather than silent: a member whose epoch is greater than its local meta but
// which cannot fetch a package REFUSES the unlock with a retryable transport error
// instead of installing the retired epoch's keys (see `person_account.rs`). The
// recovery is the owner re-running the rotation, not a silent degradation. Making
// the relay durable is a separate change: it is a storage decision (where the
// opaque records live, whether they survive `vault.meta` retention) rather than a
// line in this file.
package grouppkg

import (
	"errors"
	"sync"

	"github.com/myne-md/myne-server/internal/membership"
)

// ErrNotFound is returned for an unknown (vault, person) pair, or for the
// recipient of a package at a different vault. The two are not distinguished so
// the route leaks no enumeration signal.
var ErrNotFound = errors.New("grouppkg: package not found")

// Record is one vault-scoped, person-addressed rotation package.
type Record struct {
	Vault   membership.VaultID
	Person  membership.PersonID
	Epoch   uint64
	Package []byte // opaque owner-signed bytes, never parsed
}

type key struct {
	vault  membership.VaultID
	person membership.PersonID
}

// Store is the RAM-only package relay. Like the invite relay and the awareness
// relay it holds no payload of its own beyond the opaque bytes and does not
// survive a restart (persistence is a separate concern).
type Store struct {
	mu    sync.Mutex
	byKey map[key]Record
}

func NewStore() *Store {
	return &Store{byKey: make(map[key]Record)}
}

// Put stores pkg for (vault, person) at epoch. Latest-per-recipient: a write at
// an epoch not greater than the stored one is ignored. pkg is copied in, never
// aliased, so the caller's buffer cannot mutate a served record.
func (s *Store) Put(vault membership.VaultID, person membership.PersonID, epoch uint64, pkg []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key{vault: vault, person: person}
	if existing, ok := s.byKey[k]; ok && epoch <= existing.Epoch {
		return
	}
	buf := make([]byte, len(pkg))
	copy(buf, pkg)
	s.byKey[k] = Record{Vault: vault, Person: person, Epoch: epoch, Package: buf}
}

// Get returns the current package for (vault, person). ErrNotFound when none has
// been stored.
func (s *Store) Get(vault membership.VaultID, person membership.PersonID) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byKey[key{vault: vault, person: person}]
	if !ok {
		return Record{}, ErrNotFound
	}
	return rec, nil
}
