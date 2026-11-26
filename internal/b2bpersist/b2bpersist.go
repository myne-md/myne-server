// SPDX-License-Identifier: AGPL-3.0-only

// Package b2bpersist makes the B2B (person-to-vault) server state survive a
// restart. Without it, `membership`, the per-vault membership tokens, the invite
// relay, the person-private profile store, the group-package relay and the
// namespace-retirement registry live only in RAM, and a restart costs:
//
//   - every pending vault invite (its sealed payload exists nowhere else), so the
//     owner has to notice and re-issue it;
//   - the only copy of every member's sealed `MYY5` profile, which is DATA LOSS —
//     the bytes are keyed from the member's own phrase and the server cannot
//     reproduce them;
//   - every member's per-vault token, and the person↔vault bindings behind them;
//   - every group package, so a member cannot unwrap the current epoch until the
//     owner re-issues one;
//   - the retired-namespace set, so a stale device could write to a namespace the
//     owner rotated away from (an AVAILABILITY regression the retirement registry
//     exists to prevent) and the grace-bounded reclamation loses its due times.
//
// Kubernetes makes a restart routine rather than rare (a rolling node upgrade, a
// reschedule, an eviction), which is why this is not a nicety there. Nothing here
// changes what the server can READ: every value is either an opaque sealed blob or
// a pseudonymous id, exactly as the in-RAM stores held it.
//
// This is a SIBLING of `authpersist` rather than a merge into it, and the split is
// deliberate: auth.json is device authentication for one account
// (registry + tokens + SCRAM verifiers), while this file is the person-to-vault
// surface, which exists only when a deployment uses member vaults. One file per
// concern keeps a corrupt B2B state from refusing to start a deployment that never
// used B2B at all.
package b2bpersist

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/myne-md/myne-server/internal/grouppkg"
	"github.com/myne-md/myne-server/internal/membership"
	"github.com/myne-md/myne-server/internal/profiles"
	"github.com/myne-md/myne-server/internal/relay"
	"github.com/myne-md/myne-server/internal/store"
)

// FileName is the on-disk document, written beside the FS blob store (same volume
// as auth.json and accounts.json, so one snapshot is one backup unit). Write
// permissions are 0600, from store.AtomicWrite.
const FileName = "b2b.json"

// persistDebounce is how long the coalescing flusher waits between writes. A burst
// of B2B mutations (an invite for every member, a profile write per member device)
// collapses to at most one full-file rewrite per window. Not operator-tunable: it
// is a durability/throughput knob, not a security one.
const persistDebounce = time.Second

// schemaVersion is the envelope version. A file written by a NEWER binary fails
// closed on read rather than silently dropping fields it does not understand —
// the same posture auth.json takes (SYNC-30's store-version fail-safe).
const schemaVersion = 1

// envelope is the on-disk document: all six stores in ONE atomically written file,
// so they are crash-consistent with each other.
type envelope struct {
	Version       int                           `json:"version"`
	Bindings      []membership.PersistedBinding `json:"bindings"`
	MemberTokens  []membership.PersistedToken   `json:"member_tokens"`
	Invites       []relay.PersistedInvite       `json:"invites"`
	Profiles      []profiles.PersistedProfile   `json:"profiles"`
	GroupPackages []grouppkg.PersistedPackage   `json:"group_packages"`
	Retirements   []store.PersistedRetirement   `json:"retirements"`
}

// Stores is the set this coordinator owns. Every field is required: a nil store is
// a wiring mistake, and a partially persisted B2B surface is worse than none
// (it reads as durable and is not).
type Stores struct {
	Membership    *membership.Table
	MemberTokens  *membership.TokenStore
	Invites       *relay.Store
	Profiles      *profiles.Store
	GroupPackages *grouppkg.Store
	Retirements   *store.Retirements
}

// Coordinator owns the file and serializes saves. A single mutex makes only one
// snapshot-and-write in flight at a time, so a save is a consistent cut and the
// file is never torn.
type Coordinator struct {
	stores Stores
	path   string

	mu    sync.Mutex  // serializes saves: one consistent-cut snapshot+write
	dirty atomic.Bool // set by trigger() on a mutation; drained by the flusher / Flush
	// write is the durable-write primitive (default store.AtomicWrite). Injectable
	// so a test can count how many physical writes a burst of triggers coalesced
	// into.
	write func(path string, data []byte) error
}

// Wire loads any existing b2b.json into the stores, then installs each store's save
// hook so future mutations persist. Returns the coordinator so the caller can run
// the flusher and flush on shutdown. fs-backend only — the caller skips Wire for the
// mem backend, leaving persistence off (no hooks), so tests stay pure in-RAM.
//
// A genuinely ABSENT file is the legitimate first-boot case → start empty. A
// PRESENT-but-unparseable, wrong-width or too-new file fails closed: it refuses to
// start rather than silently coming up with no members, no profiles and a writable
// retired namespace.
func Wire(stores Stores, path string) (*Coordinator, error) {
	if stores.Membership == nil || stores.MemberTokens == nil || stores.Invites == nil ||
		stores.Profiles == nil || stores.GroupPackages == nil || stores.Retirements == nil {
		return nil, errors.New("b2bpersist: Wire requires every store; a partially persisted surface reads as durable and is not")
	}
	c := &Coordinator{stores: stores, path: path, write: store.AtomicWrite}
	if err := c.load(); err != nil {
		return nil, err
	}
	// The mutation hooks only MARK state dirty (a lock-free atomic store); the actual
	// full-file write is coalesced by the background flusher (Start) or a graceful-
	// shutdown Flush. This decouples the per-request path from the O(N) disk write.
	trigger := c.trigger
	stores.Membership.SetOnChange(trigger)
	stores.MemberTokens.SetOnChange(trigger)
	stores.Invites.SetOnChange(trigger)
	stores.Profiles.SetOnChange(trigger)
	stores.GroupPackages.SetOnChange(trigger)
	stores.Retirements.SetOnChange(trigger)
	return c, nil
}

// trigger marks the B2B state dirty. Cheap, lock-free, safe to call from a request
// handler (it does no disk IO and takes no lock), which is why the stores may call
// it while holding their own locks.
func (c *Coordinator) trigger() { c.dirty.Store(true) }

// Start runs the coalescing flusher until ctx is cancelled: at most one Save per
// persistDebounce window, plus a final flush on shutdown so no coalesced window is
// lost across a graceful stop. Run it in a goroutine.
func (c *Coordinator) Start(ctx context.Context) {
	t := time.NewTicker(persistDebounce)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.Flush() // drain any pending dirty state before exiting
			return
		case <-t.C:
			c.Flush()
		}
	}
}

// Flush writes the current state iff a mutation is pending, consuming the flag.
// Idempotent and safe to call from shutdown paths; the dirty.Swap makes a
// concurrent flusher-tick and an explicit Flush collapse to a single write.
func (c *Coordinator) Flush() {
	if c.dirty.Swap(false) {
		c.Save()
	}
}

func (c *Coordinator) load() error {
	raw, err := os.ReadFile(c.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // first boot: no b2b.json yet → start empty
	}
	if err != nil {
		// Bounded error: never the path (DENY list) or the file bytes.
		return errors.New("b2b state present but unreadable; refusing to start")
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		// NEVER wrap the json error: it can echo offending input bytes (invite
		// payloads, sealed profile bytes). A bounded, content-free message only.
		return errors.New("b2b state corrupt or unparseable; move b2b.json aside to reset collaboration state, or restore a backup")
	}
	if env.Version > schemaVersion {
		return errors.New("b2b state was written by a newer server version than this binary supports; refusing to start")
	}
	// Bindings FIRST: a membership token is only ever resolved against the binding
	// table, so loading tokens ahead of bindings would leave them dead rather than
	// dangerous (the same ordering authpersist keeps for devices-before-tokens).
	if err := c.stores.Membership.Load(env.Bindings); err != nil {
		return err
	}
	if err := c.stores.MemberTokens.Load(env.MemberTokens); err != nil {
		return err
	}
	if err := c.stores.Invites.Load(env.Invites); err != nil {
		return err
	}
	if err := c.stores.Profiles.Load(env.Profiles); err != nil {
		return err
	}
	if err := c.stores.GroupPackages.Load(env.GroupPackages); err != nil {
		return err
	}
	return c.stores.Retirements.Load(env.Retirements)
}

// Save snapshots every store under the coordinator mutex (a consistent cut, one
// writer) and atomically persists them. It is invoked by the coalescing flusher
// (Start / Flush), never directly from a request handler — the handler path only
// marks state dirty. A write failure is logged with a bounded, secret-free message
// and dropped: the in-RAM change stands; only durability across a future restart is
// at risk (bounded to the ≤1s debounce window on a crash).
func (c *Coordinator) Save() {
	c.mu.Lock()
	defer c.mu.Unlock()
	env := envelope{
		Version:       schemaVersion,
		Bindings:      c.stores.Membership.Snapshot(),
		MemberTokens:  c.stores.MemberTokens.Snapshot(),
		Invites:       c.stores.Invites.Snapshot(),
		Profiles:      c.stores.Profiles.Snapshot(),
		GroupPackages: c.stores.GroupPackages.Snapshot(),
		Retirements:   c.stores.Retirements.Snapshot(),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		log.Printf("myne-server: b2b persist marshal failed (state kept in RAM)")
		return
	}
	write := c.write
	if write == nil {
		write = store.AtomicWrite
	}
	if err := write(c.path, raw); err != nil {
		log.Printf("myne-server: b2b persist write failed (state kept in RAM)")
	}
}
