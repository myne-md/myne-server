// SPDX-License-Identifier: AGPL-3.0

package backup

import (
	"context"
	"time"
)

// Scheduler periodically drives one encrypted off-box backup via the Runner
// (MYND-505 Task 5), mirroring the gcquota.Scheduler shape. It is BEST-EFFORT: a
// failed run is reported via onError and retried on the next tick — it never
// blocks request serving or crashes the server. A bad backup target degrades
// durability, never availability.
//
// The ticker uses the server clock ONLY as an internal timer; nothing here
// surfaces a timestamp to any API response or access log (the no-wall-clock-API
// / no-persistent-IP discipline is unaffected).
type Scheduler struct {
	runner   Runner
	dataDir  string
	interval time.Duration
	onError  func(error) // best-effort failure hook (feeds a log line); may be nil
}

// NewScheduler wires the Runner + the fs store dir + a tick interval + a failure
// hook.
func NewScheduler(r Runner, dataDir string, interval time.Duration, onError func(error)) *Scheduler {
	return &Scheduler{runner: r, dataDir: dataDir, interval: interval, onError: onError}
}

// RunOnce takes one backup + prune. The error (if any) is returned so both the
// scheduled loop and a direct caller can react.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	return s.runner.Backup(ctx, s.dataDir)
}

// Start runs RunOnce on s.interval until ctx is cancelled. Run it in a goroutine.
// A failed run is reported (onError) and retried next tick; the loop never exits
// on a backup error, only on context cancellation.
func (s *Scheduler) Start(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.RunOnce(ctx); err != nil && s.onError != nil {
				s.onError(err)
			}
		}
	}
}
