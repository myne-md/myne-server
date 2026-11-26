// SPDX-License-Identifier: AGPL-3.0-only

package profiles

import (
	"errors"
	"sort"
	"time"

	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
)

// PersistedProfile is one stored profile in a JSON-safe shape, with its
// scheduled deletion (if any). The sealed bytes are the ONLY copy of a person's
// private profile, which is why this store is the most important of the four to
// persist: losing the others costs access, losing this costs data.
type PersistedProfile struct {
	Vault   []byte    `json:"vault"`
	Profile []byte    `json:"profile"`
	Writer  []byte    `json:"writer"`
	Bytes   []byte    `json:"bytes"`
	DueAt   time.Time `json:"due_at,omitempty"` // zero = no deletion scheduled
}

// ErrBadPersistedProfile is returned for a row whose ids are the wrong width.
// Fails closed.
var ErrBadPersistedProfile = errors.New("profiles: persisted row is not a valid profile")

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

// Snapshot returns every profile with its pending deletion, sorted by
// (vault, profile).
func (s *Store) Snapshot() []PersistedProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PersistedProfile, 0, len(s.rows))
	for k, row := range s.rows {
		rec := PersistedProfile{
			Vault:   k.vault[:],
			Profile: k.profile[:],
			Writer:  row.Writer[:],
			Bytes:   row.Bytes,
		}
		if due, ok := s.pending[k]; ok {
			rec.DueAt = due
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if string(out[i].Vault) != string(out[j].Vault) {
			return string(out[i].Vault) < string(out[j].Vault)
		}
		return string(out[i].Profile) < string(out[j].Profile)
	})
	return out
}

// Load replaces the store's contents from the persisted rows, restoring each
// row's pending deletion as well: a deletion scheduled before a restart must not
// be forgotten by it, or removal would leave a profile readable forever.
func (s *Store) Load(rows []PersistedProfile) error {
	next := make(map[key]Row, len(rows))
	pending := make(map[key]time.Time)
	for _, r := range rows {
		if len(r.Vault) != idLen || len(r.Profile) != idLen || len(r.Writer) != idLen {
			return ErrBadPersistedProfile
		}
		var vault ids.AccountNumberHash
		copy(vault[:], r.Vault)
		var profile ProfileID
		copy(profile[:], r.Profile)
		var writer membership.PersonID
		copy(writer[:], r.Writer)
		buf := make([]byte, len(r.Bytes))
		copy(buf, r.Bytes)
		k := key{vault: vault, profile: profile}
		next[k] = Row{Vault: vault, Profile: profile, Writer: writer, Bytes: buf}
		if !r.DueAt.IsZero() {
			pending[k] = r.DueAt
		}
	}
	s.mu.Lock()
	s.rows, s.pending = next, pending
	s.mu.Unlock()
	return nil
}
