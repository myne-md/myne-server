// SPDX-License-Identifier: AGPL-3.0-only

// Package authpersist makes device-auth state survive a server restart. Without it,
// the device registry, per-device bearer tokens, and per-account SCRAM verifiers live
// only in RAM, so any restart de-enrolls every device (clients then 401). This
// serializes all three to one atomic auth.json beside the FS blob store and reloads it
// at boot, BEFORE serving.
//
// Security posture (TB5): auth.json holds bearer tokens + SCRAM verifiers in
// plaintext at 0600. This is operator-trust-equivalent to the encrypted blob store the
// operator already holds — a token grants only sync access to ciphertext (zero
// plaintext leak; no root_key), and a SCRAM verifier is a password-hash equivalent.
// auth.json MUST inherit the same backup/secret hygiene as the blob store. v0.1 does
// not encrypt it at rest (a key on the same disk buys little vs disk compromise);
// see docs/self-host-policy.md. Tokens carry no expiry — track TTL/rotation as a
// follow-up (the real risk amplifier under a one-time disk read).
package authpersist

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

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/authapi"
	"github.com/myne-md/myne-server/internal/store"
)

// authPersistDebounce is how long the coalescing flusher waits between writes. A
// burst of auth mutations (e.g. a registration flood, even bounded by the caps)
// collapses to at most one full-file rewrite per window — this kills the O(N²)
// write amplification of a synchronous save-per-mutation. Not operator-tunable: it
// is a durability/throughput knob, not a security one.
const authPersistDebounce = time.Second

// schemaVersion is the auth.json envelope version. A file whose version exceeds this
// (written by a newer binary, then read after a rollback) fails closed rather than
// silently dropping unrecognized fields — mirroring the blob store's store-version
// SYNC-30 fail-safe.
const schemaVersion = 1

// envelope is the on-disk auth.json document: all three stores in ONE atomically
// written file so they are crash-consistent with each other.
type envelope struct {
	Version int                     `json:"version"`
	Devices []auth.PersistedDevice  `json:"devices"`
	Tokens  []auth.PersistedToken   `json:"tokens"`
	Creds   []authapi.PersistedCred `json:"creds"`
	// DeviceCreds is the per-device SCRAM verifier set (`decisions/protocol/0735`).
	// Omitted when empty, so an auth.json written before this existed round-trips
	// byte-identically through this binary and an older binary still reads the `creds`
	// array it expects.
	DeviceCreds []authapi.PersistedDeviceCred `json:"device_creds,omitempty"`
}

// Coordinator owns the auth.json file and serializes saves. A single mutex makes only
// one snapshot-and-write in flight at a time, so a save is a consistent cut and the
// file is never torn.
type Coordinator struct {
	reg     *auth.Registry
	tokens  *auth.TokenStore
	handler *authapi.Handler
	path    string

	mu    sync.Mutex  // serializes saves: one consistent-cut snapshot+write at a time
	dirty atomic.Bool // set by trigger() on a mutation; drained by the flusher / Flush
	// write is the durable-write primitive (default store.AtomicWrite). Injectable so a
	// test can count how many physical writes a burst of triggers coalesced into.
	write func(path string, data []byte) error
}

// Wire loads any existing auth.json into the three stores, then installs the save hook
// on the authapi handler so future auth mutations persist. Returns the coordinator so
// other mutators (e.g. a future GC retire path) can also call Save. fs-backend only —
// the caller skips Wire for the mem backend, leaving persistence off (onAuthChange
// nil), so tests stay pure in-RAM.
//
// A genuinely ABSENT file is the legitimate first-boot case → start empty (the
// documented one-time re-enroll). A PRESENT-but-unparseable / too-new file fails
// closed: it refuses to start rather than silently de-enrolling the fleet.
func Wire(reg *auth.Registry, tokens *auth.TokenStore, handler *authapi.Handler, path string) (*Coordinator, error) {
	c := &Coordinator{reg: reg, tokens: tokens, handler: handler, path: path, write: store.AtomicWrite}
	if err := c.load(); err != nil {
		return nil, err
	}
	// The mutation hook only MARKS state dirty (a lock-free atomic store); the actual
	// full-file write is coalesced by the background flusher (Start) or a graceful-
	// shutdown Flush. This decouples the per-request path from the O(N) disk write.
	handler.SetOnChange(c.trigger)
	return c, nil
}

// trigger marks the auth state dirty. Cheap, lock-free, safe to call from a request
// handler (it does no disk IO and takes no lock).
func (c *Coordinator) trigger() { c.dirty.Store(true) }

// Start runs the coalescing flusher until ctx is cancelled: at most one Save per
// authPersistDebounce window, plus a final flush on shutdown so no coalesced window
// is lost across a graceful stop. Run it in a goroutine.
func (c *Coordinator) Start(ctx context.Context) {
	t := time.NewTicker(authPersistDebounce)
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

// Flush writes the current state iff a mutation is pending (dirty), consuming the
// flag. Idempotent and safe to call from shutdown paths; the dirty.Swap makes a
// concurrent flusher-tick and an explicit Flush collapse to a single write.
func (c *Coordinator) Flush() {
	if c.dirty.Swap(false) {
		c.Save()
	}
}

func (c *Coordinator) load() error {
	raw, err := os.ReadFile(c.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // first boot: no auth.json yet → start empty
	}
	if err != nil {
		// Bounded error: never the path (DENY list) or file bytes.
		return errors.New("auth state present but unreadable; refusing to start")
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		// NEVER wrap the json error: it can echo offending input bytes (tokens / key
		// material). A bounded, content-free message only.
		return errors.New("auth state corrupt or unparseable; move auth.json aside to re-enroll, or restore a backup")
	}
	if env.Version > schemaVersion {
		return errors.New("auth state was written by a newer server version than this binary supports; refusing to start")
	}
	// Load registry FIRST so token referential integrity holds (a token's device must
	// resolve in the registry — AuthenticateSession rejects a token whose device is
	// absent). Direct map assignment, never the gated enroll/Issue path.
	c.reg.LoadDevices(env.Devices)
	c.tokens.LoadTokens(env.Tokens)
	c.handler.LoadCreds(env.Creds)
	c.handler.LoadDeviceCreds(env.DeviceCreds)
	return nil
}

// Save snapshots all three stores under the coordinator mutex (consistent cut, one
// writer) and atomically persists them. It is invoked by the coalescing flusher
// (Start / Flush), never directly from a request handler — the handler hook only
// marks state dirty (trigger). It MUST be called with NO auth/store locks held (it
// re-reads the stores' snapshots under their own locks). A write failure is logged
// with a bounded, secret-free message and dropped: the in-RAM change stands; only
// durability across a future restart is at risk (bounded to the ≤1s debounce window
// on a crash — at most one re-enroll, the module's existing absent-file posture).
func (c *Coordinator) Save() {
	c.mu.Lock()
	defer c.mu.Unlock()
	env := envelope{
		Version:     schemaVersion,
		Devices:     c.reg.DeviceSnapshot(),
		Tokens:      c.tokens.TokenSnapshot(),
		Creds:       c.handler.CredSnapshot(),
		DeviceCreds: c.handler.DeviceCredSnapshot(),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		log.Printf("myne-server: auth persist marshal failed (state kept in RAM)")
		return
	}
	write := c.write
	if write == nil {
		write = store.AtomicWrite
	}
	if err := write(c.path, raw); err != nil {
		log.Printf("myne-server: auth persist write failed (state kept in RAM)")
	}
}
