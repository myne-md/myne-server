// SPDX-License-Identifier: AGPL-3.0

package gcquota

import (
	"context"
	"time"

	"github.com/myne-md/myne-server/internal/ids"
)

// Scheduler periodically drives the EXISTING horizon-GC substrate (MYND-422) across
// all accounts (MYND-440, SYNC-25). It does NOT re-implement GC — it only invokes
// HorizonGC.Run on a timer and reports aggregate progress. The coarse "current
// marker" is a day bucket (server-internal, NOT a wall-clock API value, R4).
type Scheduler struct {
	gc        *HorizonGC
	accounts  func() []ids.AccountNumberHash
	onReclaim func(reclaimed int) // aggregate progress hook (feeds metrics); may be nil
	interval  time.Duration
	marker    func() uint64 // injectable for tests; defaults to the day bucket
}

// NewScheduler wires the GC + an account enumerator + an aggregate-progress hook.
func NewScheduler(gc *HorizonGC, accounts func() []ids.AccountNumberHash, onReclaim func(int), interval time.Duration) *Scheduler {
	return &Scheduler{
		gc:        gc,
		accounts:  accounts,
		onReclaim: onReclaim,
		interval:  interval,
		marker:    dayBucketMarker,
	}
}

// RunOnce performs one GC sweep across every account and returns the aggregate
// (reclaimed, retired) totals, invoking onReclaim per account's reclaimed count.
func (s *Scheduler) RunOnce() (reclaimed, retired int) {
	marker := s.marker()
	for _, a := range s.accounts() {
		r, rt := s.gc.Run(a, marker)
		reclaimed += r
		retired += rt
		if r > 0 && s.onReclaim != nil {
			s.onReclaim(r)
		}
	}
	return reclaimed, retired
}

// Start runs RunOnce on s.interval until ctx is cancelled. Run it in a goroutine.
func (s *Scheduler) Start(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.RunOnce()
		}
	}
}

// dayBucketMarker is the coarse monotone activity marker: a day bucket. It uses
// the server clock ONLY as an internal coarse counter (never an API timestamp; the
// no-IP/no-wall-clock-exposure discipline is unaffected).
func dayBucketMarker() uint64 {
	return uint64(time.Now().Unix() / 86400)
}
