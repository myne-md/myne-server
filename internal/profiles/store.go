// SPDX-License-Identifier: AGPL-3.0-only

// Package profiles is the person-private AI profile store (myne-md/myne#711,
// decisions/protocol/0592 §9.28). A profile is one sealed `MYY5` blob per
// (vault, person), stored in a vault-scoped, person-authorized namespace that
// is deliberately SEPARATE from the shared group manifest: a peer's sync never
// sees it, and the server reads none of it.
//
// The server records the WRITING person account with each row, so member
// removal can schedule that person's profile for deletion. It holds the bytes
// opaquely; the key is derived from the person's own recovery phrase and never
// reaches the server.
package profiles

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
)

// ProfileID is a 16-byte person-profile id (hex on the wire), derived
// client-side as SHA-256("myne.person-profile-id v1|" || person_id_hash ||
// account_number_hash)[:16].
type ProfileID [16]byte

// personProfileIDPrefix is the frozen domain string the id is derived under
// (`protocol.md` §9.28; `decisions/protocol/0608`). The server recomputes the
// id from the authenticated (person, vault) so a caller can only ever act on
// its OWN profile: the id is a pure function of two values the session already
// binds, so nothing else needs to be stored to enforce it.
const personProfileIDPrefix = "myne.person-profile-id v1|"

// DeriveProfileID recomputes the profile id for `(person, vault)` from the
// frozen domain. A route MUST compare the caller-supplied id against this, or
// one member could address any other member's profile (the profile namespace is
// separated from the group manifest, but the id is not a secret).
func DeriveProfileID(vault ids.AccountNumberHash, person membership.PersonID) ProfileID {
	h := sha256.New()
	h.Write([]byte(personProfileIDPrefix))
	h.Write(person[:])
	h.Write(vault[:])
	var id ProfileID
	copy(id[:], h.Sum(nil)[:len(id)])
	return id
}

type key struct {
	vault   ids.AccountNumberHash
	profile ProfileID
}

// Row is one stored profile: the opaque sealed bytes and the person account
// that wrote them.
type Row struct {
	Vault   ids.AccountNumberHash
	Profile ProfileID
	Writer  membership.PersonID
	Bytes   []byte
}

// Store is the in-memory profile table. Like the membership table it holds no
// key material it can read; persistence is a separate concern (the same
// residual the membership and relay tables carry).
type Store struct {
	mu       sync.Mutex
	rows     map[key]Row
	pending  map[key]time.Time
	onChange func()
}

// NewStore returns an empty profile store.
func NewStore() *Store {
	return &Store{rows: make(map[key]Row), pending: make(map[key]time.Time)}
}

// Put stores a profile's sealed bytes for (vault, profile), recording the
// writing person. The bytes are copied in, never aliased.
func (s *Store) Put(vault ids.AccountNumberHash, profile ProfileID, writer membership.PersonID, bytes []byte) {
	buf := make([]byte, len(bytes))
	copy(buf, bytes)
	s.mu.Lock()
	s.rows[key{vault, profile}] = Row{Vault: vault, Profile: profile, Writer: writer, Bytes: buf}
	s.changed()
	s.mu.Unlock()
}

// Get returns a stored profile, if any.
func (s *Store) Get(vault ids.AccountNumberHash, profile ProfileID) (Row, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[key{vault, profile}]
	return row, ok
}

// DeleteByPerson removes every profile the given person wrote for a vault. It is
// what removal schedules after the policy grace; it returns how many rows it
// removed. It does not touch any other person's rows.
func (s *Store) DeleteByPerson(vault ids.AccountNumberHash, person membership.PersonID) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteByPersonLocked(vault, person)
}

func (s *Store) deleteByPersonLocked(vault ids.AccountNumberHash, person membership.PersonID) int {
	n := 0
	for k, row := range s.rows {
		if k.vault == vault && row.Writer == person {
			delete(s.rows, k)
			delete(s.pending, k)
			n++
		}
	}
	if n > 0 {
		s.changed()
	}
	return n
}

// ScheduleDeletionByPerson records that every profile the given person wrote for
// a vault is to be reclaimed at `dueAt` (the removal retention grace). The
// profiles stay readable until SweepDue passes that time: deletion on removal
// makes no recall claim, and the grace is the retention-policy input
// (the operations repository#48). Scheduling is idempotent and keeps the LATEST due time.
func (s *Store) ScheduleDeletionByPerson(vault ids.AccountNumberHash, person membership.PersonID, dueAt time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, row := range s.rows {
		if k.vault == vault && row.Writer == person {
			if existing, ok := s.pending[k]; !ok || dueAt.After(existing) {
				s.pending[k] = dueAt
			}
			n++
		}
	}
	if n > 0 {
		s.changed()
	}
	return n
}

// SweepDue reclaims every profile whose scheduled deletion time is at or before
// `now`, returning how many it removed. A profile with no pending deletion is
// left alone.
func (s *Store) SweepDue(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, due := range s.pending {
		if !due.After(now) {
			delete(s.rows, k)
			delete(s.pending, k)
			n++
		}
	}
	if n > 0 {
		s.changed()
	}
	return n
}
