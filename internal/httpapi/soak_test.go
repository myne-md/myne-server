// SPDX-License-Identifier: AGPL-3.0

package httpapi

// Soak + goroutine-leak guard for a full server lifecycle. A leak that SCALES with
// requests or connections (a goroutine spawned per request/conn that never exits) is
// the dangerous one — it exhausts the server under sustained load. This drives several
// thousand concurrent requests through runListener, then a cancelled context drains
// it, and asserts the goroutine count returns near its pre-server baseline: every
// per-connection server goroutine plus the background refill ticker and GC scheduler
// has exited. The tolerance is small-constant (so a scaling leak — hundreds of
// goroutines — fails hard) but not zero (a few transient runtime goroutines are fine).

import (
	"context"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestServerLifecycle_NoGoroutineLeakUnderLoad(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	base := runtime.NumGoroutine()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runListener(ctx, ln) }()

	baseURL := "http://" + ln.Addr().String()
	waitReachable(t, baseURL)

	// Soak: thousands of concurrent requests over the unauthenticated health surface,
	// enough to churn per-connection server goroutines repeatedly.
	const workers = 32
	const perWorker = 150
	client := &http.Client{Timeout: 2 * time.Second}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				resp, err := client.Get(baseURL + "/healthz")
				if err != nil {
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	client.CloseIdleConnections()

	// Cancel → graceful shutdown must return.
	cancel()
	select {
	case <-done:
	case <-time.After(7 * time.Second):
		t.Fatal("runListener did not shut down within the window")
	}

	// Settle: background tickers + connection goroutines exit asynchronously, so poll
	// until the count drops back near baseline. A scaling leak never settles.
	if over := settleGoroutines(base+5, 3*time.Second); over > 0 {
		t.Fatalf("goroutine leak: %d still above baseline %d after %d requests + shutdown",
			over, base, workers*perWorker)
	}
}

func waitReachable(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never became reachable: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// settleGoroutines polls (with a GC each round) up to d for NumGoroutine to fall to or
// below target, returning the remaining overage (0 if it settled in time).
func settleGoroutines(target int, d time.Duration) int {
	deadline := time.Now().Add(d)
	for {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n <= target {
			return 0
		}
		if time.Now().After(deadline) {
			return n - target
		}
		time.Sleep(25 * time.Millisecond)
	}
}
