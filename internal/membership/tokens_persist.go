// SPDX-License-Identifier: AGPL-3.0

package membership

import (
	"encoding/hex"
	"errors"
	"sort"
)

// PersistedToken is one outstanding per-vault token. Persisting tokens is what
// keeps every member's existing device working across a restart; a token is a
// bearer credential for exactly one (person, vault) binding, and its binding is
// re-validated on every resolve, so a persisted token is never more authority
// than a re-issue would be.
type PersistedToken struct {
	Token  []byte `json:"token"`
	Person []byte `json:"person"`
	Vault  []byte `json:"vault"`
	Role   uint8  `json:"role"`
}

// ErrBadPersistedToken is returned for a persisted token row whose lengths do not
// describe a token, or whose role this version does not know. Fails closed.
var ErrBadPersistedToken = errors.New("membership: persisted token row is not a valid token")

// tokenLen is declared in tokens.go; these are the id widths a row must carry.
const (
	personIDLen = 16
	vaultIDLen  = 16
)

// SetOnChange installs the persistence hook (see Table.SetOnChange). Call once,
// before serving.
func (s *TokenStore) SetOnChange(fn func()) {
	s.mu.Lock()
	s.onChange = fn
	s.mu.Unlock()
}

func (s *TokenStore) changed() {
	if s.onChange != nil {
		s.onChange()
	}
}

// Snapshot returns every outstanding token, sorted by its hex form.
func (s *TokenStore) Snapshot() []PersistedToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PersistedToken, 0, len(s.byToken))
	for tok, b := range s.byToken {
		raw, err := hex.DecodeString(tok)
		if err != nil {
			// Unreachable: the key is written from hex.EncodeToString. Skipping a
			// row we cannot encode would silently drop a credential, so it is a
			// programming error and the row is encoded from what we have.
			continue
		}
		out = append(out, PersistedToken{
			Token:  raw,
			Person: b.Person[:],
			Vault:  b.Vault[:],
			Role:   uint8(b.Role),
		})
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i].Token) < string(out[j].Token) })
	return out
}

// Load replaces the token table's contents from the persisted rows. The binding
// table must be loaded first: a token is only ever resolved against it, and the
// resolve path refuses a token whose binding is absent, so a token loaded ahead of
// its binding would be dead rather than dangerous. (Same ordering the auth
// persistence module keeps for devices-before-tokens.)
func (s *TokenStore) Load(rows []PersistedToken) error {
	byToken := make(map[string]Binding, len(rows))
	for _, r := range rows {
		if len(r.Token) != tokenLen || len(r.Person) != personIDLen || len(r.Vault) != vaultIDLen {
			return ErrBadPersistedToken
		}
		if Role(r.Role) != RoleOwner && Role(r.Role) != RoleMember {
			return ErrBadPersistedToken
		}
		var person PersonID
		copy(person[:], r.Person)
		var vault VaultID
		copy(vault[:], r.Vault)
		byToken[hex.EncodeToString(r.Token)] = Binding{Person: person, Vault: vault, Role: Role(r.Role)}
	}
	s.mu.Lock()
	s.byToken = byToken
	s.mu.Unlock()
	return nil
}
