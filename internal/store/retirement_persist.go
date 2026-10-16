// SPDX-License-Identifier: AGPL-3.0

package store

import (
	"errors"
	"sort"
	"time"

	"github.com/myne-md/myne-server/internal/ids"
)

// PersistedRetiredBlob is one retired sync id and, when one is still pending, the
// instant its reclamation may run. The pair travels together because the due time is
// what a reclamation pass reads, and a restart that lost it would either reclaim early
// (data loss for a rotating member) or never (the retention promise, unkept).
//
// DueAt is a POINTER so "no pending reclamation" is expressible: a blob whose
// reclamation has already been consumed stays retired (permanently refused) with no due
// entry, and re-reporting it on every restart is what a zero time would produce.
type PersistedRetiredBlob struct {
	ID    []byte     `json:"id"`
	DueAt *time.Time `json:"due_at,omitempty"`
}

// PersistedRetirement is one vault's retirement record. `Retired` is the
// permanent set: a retired sync id is refused forever, even after its blob is
// reclaimed, so a stale push can never recreate the namespace. Losing that set
// across a restart is the availability regression this persistence exists to
// prevent: a retired namespace would become writable again.
type PersistedRetirement struct {
	Account          []byte                 `json:"account"`
	RetiredEpoch     uint64                 `json:"retired_epoch"`
	ReplacementEpoch uint64                 `json:"replacement_epoch"`
	Blobs            []PersistedRetiredBlob `json:"blobs"`
}

// ErrBadPersistedRetirement is returned for a row whose id is the wrong width.
var ErrBadPersistedRetirement = errors.New("store: persisted retirement row is not valid")

// SetOnChange installs the persistence hook. The grace window and the clock are
// configuration, not state, so they are deliberately NOT persisted. Call once,
// before serving.
func (r *Retirements) SetOnChange(fn func()) {
	r.mu.Lock()
	r.onChange = fn
	r.mu.Unlock()
}

func (r *Retirements) changed() {
	if r.onChange != nil {
		r.onChange()
	}
}

// Snapshot returns every retirement record, sorted by account, with each retired
// blob's due time.
func (r *Retirements) Snapshot() []PersistedRetirement {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]PersistedRetirement, 0, len(r.byVault))
	for account, v := range r.byVault {
		rec := PersistedRetirement{
			Account:          account[:],
			RetiredEpoch:     v.retiredEpoch,
			ReplacementEpoch: v.replacementEpoch,
		}
		for id := range v.retired {
			row := PersistedRetiredBlob{ID: id[:]}
			if due, pending := v.dueAt[id]; pending {
				dueCopy := due
				row.DueAt = &dueCopy
			}
			rec.Blobs = append(rec.Blobs, row)
		}
		sort.Slice(rec.Blobs, func(i, j int) bool { return string(rec.Blobs[i].ID) < string(rec.Blobs[j].ID) })
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i].Account) < string(out[j].Account) })
	return out
}

// Load replaces the registry's contents from the persisted rows. A retired id with NO
// pending due time loads as retired and not reclaimable, which is the state a consumed
// reclamation leaves behind: the id stays refused forever, and the blob is not reported
// a second time.
func (r *Retirements) Load(rows []PersistedRetirement) error {
	next := make(map[ids.AccountNumberHash]*vaultRetirement, len(rows))
	for _, row := range rows {
		if len(row.Account) != len(ids.AccountNumberHash{}) {
			return ErrBadPersistedRetirement
		}
		var account ids.AccountNumberHash
		copy(account[:], row.Account)
		v := &vaultRetirement{
			retiredEpoch:     row.RetiredEpoch,
			replacementEpoch: row.ReplacementEpoch,
			retired:          make(map[ids.BlobID]bool, len(row.Blobs)),
			dueAt:            make(map[ids.BlobID]time.Time, len(row.Blobs)),
		}
		for _, b := range row.Blobs {
			if len(b.ID) != len(ids.BlobID{}) {
				return ErrBadPersistedRetirement
			}
			var id ids.BlobID
			copy(id[:], b.ID)
			v.retired[id] = true
			if b.DueAt != nil {
				v.dueAt[id] = *b.DueAt
			}
		}
		next[account] = v
	}
	r.mu.Lock()
	r.byVault = next
	r.mu.Unlock()
	return nil
}
