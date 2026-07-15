// SPDX-License-Identifier: AGPL-3.0

package auth

import (
	"errors"
	"sync"

	"github.com/myne-md/myne-server/internal/ids"
)

// Registry errors.
var (
	ErrDeviceExists   = errors.New("auth: device already registered")
	ErrDeviceNotFound = errors.New("auth: device not found")
)

// DeviceRecord is one row of the per-account device registry (AS16). It holds NO
// content and NO key material — only device identity + availability/approval state
// and a COARSE last-activity marker (a single overwritten monotone value, never a
// wall-clock, never a high-resolution log — see MYND-422 R4 / ledger SYNC-7).
type DeviceRecord struct {
	DeviceID     ids.DeviceID
	Approved     bool
	Retired      bool
	LastActivity uint64 // coarse monotone marker; 0 = unseen
}

// Registry is the per-account device registry. It is the substrate the
// device-approval gate, token issuance, and the MYND-422 soft-retire consume; it
// is NOT a cryptographic version-vector roster (ledger SYNC-9).
type Registry struct {
	mu       sync.RWMutex
	accounts map[ids.AccountNumberHash]map[ids.DeviceID]*DeviceRecord
}

// NewRegistry returns an empty in-memory device registry.
func NewRegistry() *Registry {
	return &Registry{accounts: make(map[ids.AccountNumberHash]map[ids.DeviceID]*DeviceRecord)}
}

func (r *Registry) devices(account ids.AccountNumberHash) map[ids.DeviceID]*DeviceRecord {
	d := r.accounts[account]
	if d == nil {
		d = make(map[ids.DeviceID]*DeviceRecord)
		r.accounts[account] = d
	}
	return d
}

// register adds a device with a given approval state. Caller holds the gate logic.
func (r *Registry) register(account ids.AccountNumberHash, dev ids.DeviceID, approved bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.devices(account)
	if _, ok := d[dev]; ok {
		return ErrDeviceExists
	}
	d[dev] = &DeviceRecord{DeviceID: dev, Approved: approved}
	return nil
}

// Get returns a copy of a device record.
func (r *Registry) Get(account ids.AccountNumberHash, dev ids.DeviceID) (DeviceRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.accounts[account][dev]
	if !ok {
		return DeviceRecord{}, false
	}
	return *rec, true
}

// List returns copies of every device record for an account.
func (r *Registry) List(account ids.AccountNumberHash) []DeviceRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []DeviceRecord
	for _, rec := range r.accounts[account] {
		out = append(out, *rec)
	}
	return out
}

// hasAnyDevice reports whether the account has any registered device (used to
// detect the first-device self-approve case).
func (r *Registry) hasAnyDevice(account ids.AccountNumberHash) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.accounts[account]) > 0
}

// DeleteAccount removes an account's entire device registry (MYND-506). Irreversible;
// idempotent on a missing account.
func (r *Registry) DeleteAccount(account ids.AccountNumberHash) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.accounts, account)
}

// CountActiveDevices returns the number of non-retired devices for an account —
// the count that occupies the per-account device cap (MYND-506). A retired device
// frees its slot.
func (r *Registry) CountActiveDevices(account ids.AccountNumberHash) uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var n uint64
	for _, rec := range r.accounts[account] {
		if !rec.Retired {
			n++
		}
	}
	return n
}

// hasApprovedActiveDevice reports whether the account has at least one approved,
// non-retired device (the approver for a password-path enrollment).
func (r *Registry) hasApprovedActiveDevice(account ids.AccountNumberHash) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, rec := range r.accounts[account] {
		if rec.Approved && !rec.Retired {
			return true
		}
	}
	return false
}

// Approve marks a pending device approved (an existing unlocked device approving a
// new password-path device).
func (r *Registry) Approve(account ids.AccountNumberHash, dev ids.DeviceID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.accounts[account][dev]
	if !ok {
		return ErrDeviceNotFound
	}
	rec.Approved = true
	return nil
}

// Retire soft-retires a device: it stops being an approver and (via token
// revocation) its sync stops. Reused by MYND-422 horizon soft-retire (SYNC-7).
func (r *Registry) Retire(account ids.AccountNumberHash, dev ids.DeviceID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.accounts[account][dev]
	if !ok {
		return ErrDeviceNotFound
	}
	rec.Retired = true
	return nil
}

// TouchActivity sets the coarse last-activity marker — the retire/last-activity
// hook the MYND-422 horizon-GC consumes. The marker is a single overwritten
// monotone value (e.g. a coarse day bucket), never a wall-clock, never logged.
func (r *Registry) TouchActivity(account ids.AccountNumberHash, dev ids.DeviceID, marker uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.accounts[account][dev]
	if !ok {
		return ErrDeviceNotFound
	}
	if marker > rec.LastActivity {
		rec.LastActivity = marker
	}
	return nil
}

// --- Persistence snapshot/restore (MYND auth-persistence) ---
//
// The registry holds NO key material (only device identity + approval state), so a
// PersistedDevice is safe to serialize. LastActivity is deliberately NOT persisted: it
// is a loss-tolerant coarse GC marker, and a restored device's LastActivity resets to
// 0 ("unseen"), which the horizon-GC treats as not-a-retire-candidate.

// PersistedDevice is the serializable form of one registry row, carrying the account
// (which the in-RAM DeviceRecord does not) so a flat snapshot round-trips.
type PersistedDevice struct {
	Account  ids.AccountNumberHash
	DeviceID ids.DeviceID
	Approved bool
	Retired  bool
}

// DeviceSnapshot returns a flat copy of every device row across all accounts.
func (r *Registry) DeviceSnapshot() []PersistedDevice {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []PersistedDevice
	for acct, devs := range r.accounts {
		for _, rec := range devs {
			out = append(out, PersistedDevice{
				Account:  acct,
				DeviceID: rec.DeviceID,
				Approved: rec.Approved,
				Retired:  rec.Retired,
			})
		}
	}
	return out
}

// LoadDevices REPLACES the registry contents from a snapshot by direct assignment
// (never through the gated register/Approve path). Idempotent: a second load yields
// the same state. Used only at boot, before serving.
func (r *Registry) LoadDevices(snap []PersistedDevice) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accounts = make(map[ids.AccountNumberHash]map[ids.DeviceID]*DeviceRecord)
	for _, d := range snap {
		m := r.accounts[d.Account]
		if m == nil {
			m = make(map[ids.DeviceID]*DeviceRecord)
			r.accounts[d.Account] = m
		}
		m[d.DeviceID] = &DeviceRecord{DeviceID: d.DeviceID, Approved: d.Approved, Retired: d.Retired}
	}
}
