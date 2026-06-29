// SPDX-License-Identifier: AGPL-3.0

package httpapi

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestGracefulShutdown: runListener serves, then a cancelled context drains
// in-flight requests and returns cleanly within the shutdown window.
func TestGracefulShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- runListener(ctx, ln) }()

	// Server is up: /healthz answers.
	base := "http://" + ln.Addr().String()
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never became reachable: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// /readyz reports ready.
	if resp, err := http.Get(base + "/readyz"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz not ready before shutdown: status=%v err=%v", statusOf(resp), err)
	}

	// Cancel → graceful shutdown must return cleanly (nil) within the window.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful shutdown returned error: %v", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("runListener did not shut down within the window")
	}
}

func statusOf(r *http.Response) int {
	if r == nil {
		return 0
	}
	defer func() { _ = r.Body.Close() }()
	return r.StatusCode
}
