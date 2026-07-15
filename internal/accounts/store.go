// SPDX-License-Identifier: AGPL-3.0

// Package accounts persists per-account OPERATOR ENFORCEMENT policy (MYND-506):
// freeze state and per-account quota / device-cap overrides, plus reserved billing
// fields (plan_id / paid_until_day, written by MYND-430 later). It mirrors
// internal/authpersist — a single top-level accounts.json beside the blob store, an
// in-memory map, a consistent-cut atomic snapshot, and a coalescing flusher.
//
// Posture (TB5/TB6): this is server-side PLAINTEXT operator metadata of the same
// class as the device count / stored-byte size the server already holds — never user
// content, never a new observation channel (no request history / wall-clocks / time
// series; the MYND-440 aggregate-only invariant). The store is SPARSE: only accounts
// with non-default policy keep an entry, so absence means "all defaults". Not synced
// (operator policy, not user data); it lands in the built-in backup automatically
// (same volume).
package accounts

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// flushDebounce coalesces a burst of policy mutations into at most one full-file
// rewrite per window (the authpersist discipline). Durability/throughput knob, not a
// security one.
const flushDebounce = time.Second

// schemaVersion is the accounts.json envelope version. A file whose version exceeds
// this (written by a newer binary, then read after a rollback) fails closed rather
// than silently dropping fields — mirroring the store-version SYNC-30 fail-safe.
const schemaVersion = 1

// Policy is the per-account operator enforcement state. All-zero == defaults.
type Policy struct {
	Frozen             bool   `json:"frozen,omitempty"`
	QuotaOverrideBytes uint64 `json:"quota_override_bytes,omitempty"`
	MaxDevicesOverride uint64 `json:"max_devices_override,omitempty"`
	PlanID             string `json:"plan_id,omitempty"`        // reserved — MYND-430 writes it
	PaidUntilDay       uint64 `json:"paid_until_day,omitempty"` // reserved — MYND-430 writes it
}

// IsDefault reports whether p carries no operator policy. Such an account keeps NO
// entry, so accounts.json stays sparse.
func (p Policy) IsDefault() bool { return p == Policy{} }

// envelope is the on-disk accounts.json document.
type envelope struct {
	Version  int               `json:"version"`
	Accounts map[string]Policy `json:"accounts"`
}

// Store holds per-account operator policy, sparse, persisted to accounts.json.
type Store struct {
	path  string
	mu    sync.RWMutex
	m     map[ids.AccountNumberHash]Policy // per-account policy (non-default only)
	dirty atomic.Bool
	// write is the durable-write primitive (default store.AtomicWrite). Injectable so a
	// test can count how many physical writes a burst of mutations coalesced into.
	write func(path string, data []byte) error
}

// New builds an empty store at path. Call Load to hydrate from disk.
func New(path string) *Store {
	return &Store{path: path, m: make(map[ids.AccountNumberHash]Policy), write: store.AtomicWrite}
}

// Load reads accounts.json. A genuinely ABSENT file is the legitimate first-boot case
// → start empty. A PRESENT-but-unparseable / too-new file fails closed (refuses to
// start rather than silently dropping operator policy).
func (s *Store) Load() error {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("account policy present but unreadable; refusing to start")
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return errors.New("account policy corrupt or unparseable; move accounts.json aside or restore a backup")
	}
	if env.Version > schemaVersion {
		return errors.New("account policy was written by a newer server version than this binary supports; refusing to start")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = make(map[ids.AccountNumberHash]Policy, len(env.Accounts))
	for k, p := range env.Accounts {
		h, ok := ids.ParseAccountNumberHash(k)
		if !ok {
			return errors.New("account policy has a malformed account key; move accounts.json aside or restore a backup")
		}
		if !p.IsDefault() {
			s.m[h] = p // drop any default-valued entries so the map stays sparse
		}
	}
	return nil
}

// Get returns the account's policy — the zero value (all defaults) when absent.
func (s *Store) Get(h ids.AccountNumberHash) Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[h]
}

// Frozen reports whether the account is frozen (blocks push + enroll, never pull).
func (s *Store) Frozen(h ids.AccountNumberHash) bool { return s.Get(h).Frozen }

// EffectiveQuota returns the account's quota ceiling: its override when set (> 0),
// else base. 0 either way means unlimited. Used by the quota guard so a per-account
// override wins over the global default.
func (s *Store) EffectiveQuota(h ids.AccountNumberHash, base uint64) uint64 {
	if o := s.Get(h).QuotaOverrideBytes; o > 0 {
		return o
	}
	return base
}

// EffectiveMaxDevices returns the account's device cap: its override when set (> 0),
// else base. 0 either way means unlimited.
func (s *Store) EffectiveMaxDevices(h ids.AccountNumberHash, base uint64) uint64 {
	if o := s.Get(h).MaxDevicesOverride; o > 0 {
		return o
	}
	return base
}

// Update applies mutate to the account's current policy and marks the store dirty
// (persisted by the flusher). If the result is default, the entry is REMOVED so the
// file stays sparse. Returns the resulting policy.
func (s *Store) Update(h ids.AccountNumberHash, mutate func(*Policy)) Policy {
	s.mu.Lock()
	p := s.m[h]
	mutate(&p)
	if p.IsDefault() {
		delete(s.m, h)
	} else {
		s.m[h] = p
	}
	s.mu.Unlock()
	s.dirty.Store(true)
	return p
}

// Delete removes an account's policy entry (account purge — admin delete).
func (s *Store) Delete(h ids.AccountNumberHash) {
	s.mu.Lock()
	delete(s.m, h)
	s.mu.Unlock()
	s.dirty.Store(true)
}

// Start runs the coalescing flusher until ctx is cancelled: at most one Save per
// window, plus a final flush on shutdown so no coalesced window is lost. Run it in a
// goroutine.
func (s *Store) Start(ctx context.Context) {
	t := time.NewTicker(flushDebounce)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.Flush()
			return
		case <-t.C:
			s.Flush()
		}
	}
}

// Flush persists the current state iff a mutation is pending, consuming the flag.
func (s *Store) Flush() {
	if s.dirty.Swap(false) {
		s.save()
	}
}

func (s *Store) save() {
	s.mu.RLock()
	env := envelope{Version: schemaVersion, Accounts: make(map[string]Policy, len(s.m))}
	for h, p := range s.m {
		env.Accounts[hex.EncodeToString(h[:])] = p // hex-keyed only at the on-disk boundary
	}
	s.mu.RUnlock()
	raw, err := json.Marshal(env)
	if err != nil {
		log.Printf("myne-server: account policy marshal failed (state kept in RAM)")
		return
	}
	if err := s.write(s.path, raw); err != nil {
		log.Printf("myne-server: account policy write failed (state kept in RAM)")
	}
}
