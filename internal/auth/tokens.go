// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"sync"

	"github.com/myne-md/myne-server/internal/ids"
)

// TokenLen is the byte length of a per-device token (256-bit, high-entropy).
const TokenLen = 32

// tokenBinding records what a token authenticates.
type tokenBinding struct {
	account ids.AccountNumberHash
	device  ids.DeviceID
}

// TokenStore issues + validates per-device tokens and is the Authenticator the
// push/pull/poke handlers consume. A token is the revocable bearer credential
// (distinct from device_id, ledger SYNC-2); revoking it never touches the
// device_id. Validation also rejects tokens for retired devices.
type TokenStore struct {
	mu       sync.RWMutex
	byToken  map[string]tokenBinding
	registry *Registry
}

// NewTokenStore returns a token store backed by the given device registry (used to
// reject tokens whose device has been retired).
func NewTokenStore(reg *Registry) *TokenStore {
	return &TokenStore{byToken: make(map[string]tokenBinding), registry: reg}
}

// Issue mints a fresh random per-device token bound to (account, device).
func (s *TokenStore) Issue(account ids.AccountNumberHash, dev ids.DeviceID) (ids.DeviceToken, error) {
	raw := make([]byte, TokenLen)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.byToken[hex.EncodeToString(raw)] = tokenBinding{account: account, device: dev}
	s.mu.Unlock()
	return ids.DeviceToken(raw), nil
}

// Session is a validated session — the bound account + device.
type Session struct {
	Account ids.AccountNumberHash
	Device  ids.DeviceID
}

// Authenticate validates a token and returns the bound account (Authenticator).
func (s *TokenStore) Authenticate(token ids.DeviceToken) (ids.AccountNumberHash, error) {
	sess, err := s.AuthenticateSession(token)
	if err != nil {
		return ids.AccountNumberHash{}, err
	}
	return sess.Account, nil
}

// AuthenticateSession validates a token and returns the bound (account, device). It
// rejects an unknown token and a token whose device has been retired/revoked.
func (s *TokenStore) AuthenticateSession(token ids.DeviceToken) (Session, error) {
	if len(token) != TokenLen {
		return Session{}, ErrUnauthenticated
	}
	key := hex.EncodeToString(token)
	s.mu.RLock()
	b, ok := s.byToken[key]
	s.mu.RUnlock()
	if !ok {
		return Session{}, ErrUnauthenticated
	}
	// The token's device must still be a known, non-retired registry row. Before
	// auth state was persisted, the byToken + registry maps were built together in
	// RAM and could not drift; once they round-trip through disk independently, a
	// token whose device record is absent (a torn/partial load) must NOT authenticate
	// — reject when the device is missing OR retired (fail-closed, not fail-open).
	rec, found := s.registry.Get(b.account, b.device)
	if !found || rec.Retired {
		return Session{}, ErrUnauthenticated
	}
	return Session{Account: b.account, Device: b.device}, nil
}

// Revoke invalidates a specific token (e.g. on "Remove device"). It does NOT touch
// the device_id (re-enroll is governed by the approval gate, not a device_id block).
func (s *TokenStore) Revoke(token ids.DeviceToken) {
	s.mu.Lock()
	delete(s.byToken, hex.EncodeToString(token))
	s.mu.Unlock()
}

// RevokeDevice invalidates every token bound to a device (used by "Remove device"
// + MYND-422 soft-retire). Availability-only: it stops that device's sync; it is
// not a cryptographic lock (v0.1 has no forward secrecy).
func (s *TokenStore) RevokeDevice(account ids.AccountNumberHash, dev ids.DeviceID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, b := range s.byToken {
		if b.account == account && subtleEqualDevice(b.device, dev) {
			delete(s.byToken, k)
		}
	}
}

func subtleEqualDevice(a, b ids.DeviceID) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// --- Persistence snapshot/restore (MYND auth-persistence) ---

// PersistedToken is the serializable form of one token binding. TokenHex is the raw
// map key (the hex of the 256-bit token) — it is a bearer credential; never log it.
type PersistedToken struct {
	TokenHex string
	Account  ids.AccountNumberHash
	Device   ids.DeviceID
}

// TokenSnapshot returns a copy of every live token binding.
func (s *TokenStore) TokenSnapshot() []PersistedToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PersistedToken, 0, len(s.byToken))
	for tok, b := range s.byToken {
		out = append(out, PersistedToken{TokenHex: tok, Account: b.account, Device: b.device})
	}
	return out
}

// LoadTokens REPLACES the token map from a snapshot by direct assignment (never
// through Issue, so no new tokens are minted). Idempotent. Boot-only.
func (s *TokenStore) LoadTokens(snap []PersistedToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byToken = make(map[string]tokenBinding, len(snap))
	for _, t := range snap {
		s.byToken[t.TokenHex] = tokenBinding{account: t.Account, device: t.Device}
	}
}

var _ Authenticator = (*TokenStore)(nil)
