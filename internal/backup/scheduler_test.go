// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScheduler_RunOnceTakesBackup(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls.log")
	r := sampleRunner()
	r.ResticBin = writeStubRestic(t, log, 0)

	s := NewScheduler(r, "/data", time.Hour, nil)
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	got, _ := os.ReadFile(log)
	if string(got) != "backup\nforget\n" {
		t.Errorf("calls = %q, want backup then forget", got)
	}
}

func TestScheduler_StartReturnsOnCancel(t *testing.T) {
	r := sampleRunner()
	r.ResticBin = writeStubRestic(t, filepath.Join(t.TempDir(), "l"), 0)
	s := NewScheduler(r, "/data", time.Hour, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled → Start must return promptly

	done := make(chan struct{})
	go func() { s.Start(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return on a cancelled context")
	}
}

// TestScheduler_FiresOnTickAndKeepsRunningOnError proves three things at once:
// the loop fires on the tick, a backup failure is reported via onError (not a
// panic/exit), and the loop keeps running after a failure (a second tick fires).
func TestScheduler_FiresOnTickAndKeepsRunningOnError(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls.log")
	r := sampleRunner()
	r.ResticBin = writeStubRestic(t, log, 3) // every run fails

	fired := make(chan error, 8)
	s := NewScheduler(r, "/data", 5*time.Millisecond, func(e error) { fired <- e })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx)

	for i := 0; i < 2; i++ { // two consecutive ticks must both fire + report
		select {
		case err := <-fired:
			if err == nil {
				t.Fatalf("tick %d: expected a reported backup error", i)
			}
			if !strings.Contains(err.Error(), "restic") {
				t.Errorf("tick %d: error should come from restic: %v", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("scheduler did not fire on tick %d (stopped after a failure?)", i)
		}
	}
}
