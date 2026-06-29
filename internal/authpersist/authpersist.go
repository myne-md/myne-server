// SPDX-License-Identifier: AGPL-3.0

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
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"sync"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/authapi"
	"github.com/myne-md/myne-server/internal/store"
)

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
}

// Coordinator owns the auth.json file and serializes saves. A single mutex makes only
// one snapshot-and-write in flight at a time, so a save is a consistent cut and the
// file is never torn.
type Coordinator struct {
	reg     *auth.Registry
	tokens  *auth.TokenStore
	handler *authapi.Handler
	path    string

	mu sync.Mutex // serializes saves: one consistent-cut snapshot+write at a time
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
	c := &Coordinator{reg: reg, tokens: tokens, handler: handler, path: path}
	if err := c.load(); err != nil {
		return nil, err
	}
	handler.SetOnChange(c.Save)
	return c, nil
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
	return nil
}

// Save snapshots all three stores under the coordinator mutex (consistent cut, one
// writer) and atomically persists them. It MUST be called with NO auth/store locks
// held (the authapi handlers invoke it via a deferred hook that runs after their own
// unlock). A write failure is logged with a bounded, secret-free message and dropped:
// the in-RAM change stands; only durability across a future restart is at risk.
func (c *Coordinator) Save() {
	c.mu.Lock()
	defer c.mu.Unlock()
	env := envelope{
		Version: schemaVersion,
		Devices: c.reg.DeviceSnapshot(),
		Tokens:  c.tokens.TokenSnapshot(),
		Creds:   c.handler.CredSnapshot(),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		log.Printf("myne-server: auth persist marshal failed (state kept in RAM)")
		return
	}
	if err := store.AtomicWrite(c.path, raw); err != nil {
		log.Printf("myne-server: auth persist write failed (state kept in RAM)")
	}
}
