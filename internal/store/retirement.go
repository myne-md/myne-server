// SPDX-License-Identifier: AGPL-3.0

package store

import (
	"sync"
	"time"

	"github.com/myne-md/myne-server/internal/ids"
)

// DefaultRetirementGrace is how long a retired namespace's blobs are retained
// before reclamation. It is a RECOVERY window, not a retention policy: every
// live member can obtain the new epoch's blobs without ever reading the old
// namespace, so the grace exists only to let an in-flight rotation finish.
// A self-host operator may widen or shorten it; the protocol fixes only that it
// is bounded (decisions/protocol/0594, Grill 3 Q16/S1).
const DefaultRetirementGrace = 7 * 24 * time.Hour

// Retirements is the server-side namespace-retirement registry (myne-md/myne#711,
// decisions/protocol/0599). It records, per vault, the retired key epoch and the
// old sync ids the owner asked to retire, then enforces two availability rules:
//
//   - a write to a retired sync id is refused, so a stale device cannot
//     resurrect a namespace the owner has rotated away from;
//   - the retired blobs are reclaimed only after the grace window has elapsed.
//
// The server verifies NO signature and holds NO public key here: the owner's
// authenticated session is the authority, and the owner-double-signed retirement
// record stays the PEER-verifiable artefact that travels the blob plane. This
// type therefore stores the record's fields for provenance but keys enforcement
// on the sync ids the owner named, which is what a write can be matched against.
type Retirements struct {
	mu       sync.Mutex
	grace    time.Duration
	now      func() time.Time
	byVault  map[ids.AccountNumberHash]*vaultRetirement
	onChange func()
}

type vaultRetirement struct {
	retiredEpoch     uint64
	replacementEpoch uint64
	// retired is the permanent set: a retired sync id is refused forever, even
	// after its blob is reclaimed, so a stale push can never recreate it.
	retired map[ids.BlobID]bool
	// dueAt maps a retired blob to the instant reclamation may run.
	dueAt map[ids.BlobID]time.Time
}

// NewRetirements returns an empty registry with the given grace window (<= 0
// falls back to DefaultRetirementGrace).
func NewRetirements(grace time.Duration) *Retirements {
	if grace <= 0 {
		grace = DefaultRetirementGrace
	}
	return &Retirements{
		grace:   grace,
		now:     time.Now,
		byVault: make(map[ids.AccountNumberHash]*vaultRetirement),
	}
}

// WithClock overrides the registry clock (tests inject a fake so the grace
// boundary is deterministic).
func (r *Retirements) WithClock(now func() time.Time) *Retirements {
	if now != nil {
		r.now = now
	}
	return r
}

// Record registers a retirement: retiredEpoch/replacementEpoch for provenance,
// and reclaim as the old sync ids to refuse and later reclaim. Re-recording a
// vault extends the retired set and raises the retired epoch; a lower epoch is
// ignored so an out-of-order call cannot walk the floor back.
func (r *Retirements) Record(account ids.AccountNumberHash, retiredEpoch, replacementEpoch uint64, reclaim []ids.BlobID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.byVault[account]
	if v == nil {
		v = &vaultRetirement{retired: make(map[ids.BlobID]bool), dueAt: make(map[ids.BlobID]time.Time)}
		r.byVault[account] = v
	}
	if retiredEpoch > v.retiredEpoch {
		v.retiredEpoch = retiredEpoch
		v.replacementEpoch = replacementEpoch
	}
	due := r.now().Add(r.grace)
	for _, id := range reclaim {
		v.retired[id] = true
		v.dueAt[id] = due
	}
	r.changed()
}

// IsRetired reports whether a sync id is retired for the vault, and so may not
// be written. It is permanent for a recorded id.
func (r *Retirements) IsRetired(account ids.AccountNumberHash, id ids.BlobID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.byVault[account]
	if v == nil {
		return false
	}
	return v.retired[id]
}

// HighestRetiredEpoch returns the highest retired epoch recorded for the vault
// and whether one is recorded.
func (r *Retirements) HighestRetiredEpoch(account ids.AccountNumberHash) (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.byVault[account]
	if v == nil || v.retiredEpoch == 0 {
		return 0, false
	}
	return v.retiredEpoch, true
}

// DueRetirements returns every retired blob whose grace has elapsed, WITHOUT consuming it.
// The caller reclaims the blob and then calls Reclaimed, so a reclaim that fails stays due
// and is retried on the next pass.
//
// It replaced a consuming `DueReclaims` (myne-md/myne-server#17). Consuming first is the
// wrong order: the caller's next step is the storage write that can fail, and a consumed id
// whose reclaim failed is never reported again — a silent permanent leak, which is exactly
// what the gap this closes looked like from the outside (the retention promise, unkept).
func (r *Retirements) DueRetirements() map[ids.AccountNumberHash][]ids.BlobID {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var out map[ids.AccountNumberHash][]ids.BlobID
	for account, v := range r.byVault {
		for id, due := range v.dueAt {
			if !now.Before(due) {
				if out == nil {
					out = make(map[ids.AccountNumberHash][]ids.BlobID)
				}
				out[account] = append(out[account], id)
			}
		}
	}
	return out
}

// Reclaimed records that a due blob's body has been reclaimed, so it is not reported again.
// The id stays in the permanent retired set — a stale push to it is still refused forever —
// and only its due time is dropped. Idempotent: marking an id twice (or one that was never
// due) is not an error, because the caller's reclaim is itself idempotent.
func (r *Retirements) Reclaimed(account ids.AccountNumberHash, id ids.BlobID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.byVault[account]
	if v == nil {
		return
	}
	if _, ok := v.dueAt[id]; !ok {
		return
	}
	delete(v.dueAt, id)
	r.changed()
}
