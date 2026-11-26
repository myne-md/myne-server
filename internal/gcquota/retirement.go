// SPDX-License-Identifier: AGPL-3.0-only

package gcquota

import (
	"context"
	"time"

	"github.com/myne-md/myne-server/internal/ids"
)

// RetirementReclaimer drives the retirement registry's DUE list into the store
// (myne-md/myne-server#17). Before it existed, `Retirements` recorded a grace window and
// nothing ever read it: retired ciphertext was refused for writes, forever, and never
// physically released, so the documented window was a comment.
//
// Order matters, and it is the reason the registry exposes a peek and an ack rather than one
// consuming call: reclaim FIRST, then mark reclaimed. A reclaim that fails (disk error, blob
// absent because it never arrived) leaves the id due, so the next pass retries it. Consuming
// first would drop an id whose reclaim failed, which is a permanent silent leak — the same
// shape as the gap itself.
type RetirementReclaimer struct {
	// due returns the retired ids whose grace has elapsed, without consuming them.
	due func() map[ids.AccountNumberHash][]ids.BlobID
	// reclaim drops one blob's body. ErrNotFound is "nothing to free", not a failure: a
	// namespace can be retired before any blob arrives in it.
	reclaim func(account ids.AccountNumberHash, blobID ids.BlobID) error
	// ack records that the id's body is gone, so it is not reported again.
	ack func(account ids.AccountNumberHash, blobID ids.BlobID)
	// notFound reports whether an error means "no such blob" (nothing to reclaim).
	notFound func(error) bool
	// onReclaim feeds aggregate metrics: one call per reclamation, with the id's reclaimed
	// count. Never an account-labelled value (the aggregate-only invariant).
	onReclaim func(n int)
	interval  time.Duration
}

// NewRetirementReclaimer wires the registry's due list to a store's reclaim operation. All
// four functions are required; `onReclaim` may be nil.
func NewRetirementReclaimer(
	due func() map[ids.AccountNumberHash][]ids.BlobID,
	reclaim func(account ids.AccountNumberHash, blobID ids.BlobID) error,
	ack func(account ids.AccountNumberHash, blobID ids.BlobID),
	notFound func(error) bool,
	onReclaim func(int),
	interval time.Duration,
) *RetirementReclaimer {
	return &RetirementReclaimer{
		due:       due,
		reclaim:   reclaim,
		ack:       ack,
		notFound:  notFound,
		onReclaim: onReclaim,
		interval:  interval,
	}
}

// RunOnce performs one reclamation pass and returns how many blobs it reclaimed (acked) and
// how many it could not (left due for the next pass, or dropped because the blob was absent).
//
// A blob the store does not hold is ACKED, because there is nothing to free and re-reporting
// it forever would make every pass touch the same dead id; a blob whose reclaim returned any
// other error is left due, so a transient disk failure is retried rather than forgotten.
func (r *RetirementReclaimer) RunOnce() (reclaimed, absent int) {
	for account, blobIDs := range r.due() {
		for _, id := range blobIDs {
			err := r.reclaim(account, id)
			switch {
			case err == nil:
				reclaimed++
			case r.notFound != nil && r.notFound(err):
				// Nothing to free. Ack it so it is not reported again, and count it
				// separately: an absent blob is not a reclamation.
				absent++
			default:
				continue // left due: retried next pass
			}
			r.ack(account, id)
			if err == nil && r.onReclaim != nil {
				r.onReclaim(1)
			}
		}
	}
	return reclaimed, absent
}

// Start runs RunOnce on s.interval until ctx is cancelled. Run it in a goroutine.
func (r *RetirementReclaimer) Start(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.RunOnce()
		}
	}
}
