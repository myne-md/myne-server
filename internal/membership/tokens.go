// SPDX-License-Identifier: AGPL-3.0

package membership

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/myne-md/myne-server/internal/ids"
)

// ErrUnauthenticated is returned for an unknown or revoked membership token.
var ErrUnauthenticated = errors.New("membership: unauthenticated")

// tokenLen is the byte length of a per-vault membership token (256-bit).
const tokenLen = 32

// TokenStore issues per-vault bearer tokens bound to a (person, vault) binding.
// It is the server-side availability control: a token grants access to exactly
// one vault for exactly one person, so removing a member revokes that person's
// access to that vault and nothing else (decisions/protocol/0599).
type TokenStore struct {
	mu       sync.RWMutex
	byToken  map[string]Binding
	table    *Table
	onRevoke func(tokenHex string)
	onChange func()
}

// SetOnRevoke installs an observer called with each revoked token's hex when
// Revoke removes it. The live-awareness relay uses it to close a removed
// member's open streams at once, keying on the token so it stays person-agnostic.
func (s *TokenStore) SetOnRevoke(fn func(tokenHex string)) {
	s.mu.Lock()
	s.onRevoke = fn
	s.mu.Unlock()
}

// NewTokenStore returns a token store whose tokens are validated against the
// membership table (a token whose binding was removed is refused).
func NewTokenStore(table *Table) *TokenStore {
	return &TokenStore{byToken: make(map[string]Binding), table: table}
}

// Issue mints a fresh per-vault token for an existing binding. A binding the
// table does not hold, or whose role has since changed, is refused: a token is
// only ever minted for access that currently exists.
func (s *TokenStore) Issue(person PersonID, vault VaultID) (ids.DeviceToken, error) {
	if _, ok := s.table.Role(vault, person); !ok {
		return nil, ErrNotBound
	}
	raw := make([]byte, tokenLen)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.byToken[hex.EncodeToString(raw)] = Binding{
		Person: person,
		Vault:  vault,
	}
	s.changed()
	s.mu.Unlock()
	return ids.DeviceToken(raw), nil
}

// Resolve validates a token and returns the binding it authenticates. It refuses
// an unknown token AND a token whose binding no longer exists in the table, so a
// removal invalidates outstanding tokens without a separate revoke sweep.
func (s *TokenStore) Resolve(token ids.DeviceToken) (Binding, error) {
	if len(token) != tokenLen {
		return Binding{}, ErrUnauthenticated
	}
	s.mu.RLock()
	b, ok := s.byToken[hex.EncodeToString(token)]
	s.mu.RUnlock()
	if !ok {
		return Binding{}, ErrUnauthenticated
	}
	role, bound := s.table.Role(b.Vault, b.Person)
	if !bound {
		return Binding{}, ErrUnauthenticated
	}
	b.Role = role
	return b, nil
}

// Revoke deletes every outstanding token for one (person, vault) binding. This
// is the targeted revoke removal performs: it touches one vault's access for one
// person, never the person's other vaults.
func (s *TokenStore) Revoke(vault VaultID, person PersonID) {
	s.mu.Lock()
	var revoked []string
	for tok, b := range s.byToken {
		if b.Vault == vault && b.Person == person {
			delete(s.byToken, tok)
			revoked = append(revoked, tok)
		}
	}
	onRevoke := s.onRevoke
	s.mu.Unlock()
	// A revocation changes what a restart must reproduce: the token is gone, and if
	// that were only in RAM, a restart would resurrect a credential the owner
	// deliberately revoked.
	if len(revoked) > 0 {
		s.changed()
	}
	// Report after releasing the lock: the observer (the awareness relay) takes
	// its own locks and must never run under the token store's.
	if onRevoke != nil {
		for _, tok := range revoked {
			onRevoke(tok)
		}
	}
}
