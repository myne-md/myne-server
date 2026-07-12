// SPDX-License-Identifier: AGPL-3.0

package poke

import (
	"bufio"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/gcquota"
	"github.com/myne-md/myne-server/internal/ids"
)

func acct(b byte) ids.AccountNumberHash {
	var a ids.AccountNumberHash
	a[0] = b
	return a
}

func TestNotifier_SignalsSubscriber(t *testing.T) {
	n := NewNotifier()
	a := acct(1)
	ch, ok := n.subscribe(a)
	if !ok {
		t.Fatal("subscribe rejected under the default cap")
	}
	defer n.unsubscribe(a, ch)

	if n.SubscriberCount(a) != 1 {
		t.Fatalf("subscriber count = %d, want 1", n.SubscriberCount(a))
	}
	n.Notify(a)
	select {
	case _, ok := <-ch:
		if !ok {
			t.Fatal("channel closed")
		}
		// The signal is struct{}{} — literally zero payload (no id/version/count).
	default:
		t.Fatal("no poke delivered")
	}
}

func TestNotifier_Coalesces(t *testing.T) {
	n := NewNotifier()
	a := acct(2)
	ch, _ := n.subscribe(a)
	defer n.unsubscribe(a, ch)
	// Two notifies before a read → coalesced to a single pending signal (buffer 1).
	n.Notify(a)
	n.Notify(a)
	<-ch // one
	select {
	case <-ch:
		t.Fatal("second (coalesced) poke should not be pending")
	default:
	}
}

func TestNotifier_IsolatedPerAccount(t *testing.T) {
	n := NewNotifier()
	a, b := acct(3), acct(4)
	chA, _ := n.subscribe(a)
	defer n.unsubscribe(a, chA)
	n.Notify(b) // different account
	select {
	case <-chA:
		t.Fatal("account A got account B's poke")
	default:
	}
}

func TestNotifier_CapEnforcedAndReleased(t *testing.T) {
	n := NewNotifier().WithMaxSubscribers(2)
	a := acct(5)
	ch1, ok1 := n.subscribe(a)
	ch2, ok2 := n.subscribe(a)
	if !ok1 || !ok2 {
		t.Fatal("subscribes under the cap must succeed")
	}
	if _, ok := n.subscribe(a); ok {
		t.Fatal("third subscribe should be rejected at cap 2")
	}
	n.unsubscribe(a, ch1)
	ch3, ok := n.subscribe(a)
	if !ok {
		t.Fatal("subscribe after a release should succeed")
	}
	n.unsubscribe(a, ch2)
	n.unsubscribe(a, ch3)
	if got := n.SubscriberCount(a); got != 0 {
		t.Fatalf("subscriber count after full release = %d, want 0", got)
	}
}

// --- Handler-level tests (httptest + real SSE reads) ---

func enrolled(t *testing.T) (*auth.TokenStore, string, ids.AccountNumberHash) {
	t.Helper()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)
	a := acct(0x42)
	var d ids.DeviceID
	d[0] = 0x01
	res, err := en.Enroll(a, d, auth.PathPassword)
	if err != nil {
		t.Fatal(err)
	}
	return ts, hex.EncodeToString(res.Token), a
}

// openStream GETs /sync/poke and returns the live response (caller closes).
func openStream(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url+"/sync/poke", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// readLine reads one non-empty line off the SSE stream with a deadline enforced
// by the test's overall timeout (the reads block on the streaming body).
func readLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("stream read: %v", err)
		}
		if s := strings.TrimRight(line, "\r\n"); s != "" {
			return s
		}
	}
}

func TestHandler_PokeDeliveredOverSSE(t *testing.T) {
	ts, token, a := enrolled(t)
	n := NewNotifier()
	mux := http.NewServeMux()
	NewHandler(n, ts).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := openStream(t, srv.URL, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type %q", ct)
	}

	// Wait for the handler's subscribe to land, then notify.
	deadline := time.Now().Add(2 * time.Second)
	for n.SubscriberCount(a) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("handler never subscribed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	n.Notify(a)

	if line := readLine(t, bufio.NewReader(resp.Body)); line != "data:" {
		t.Fatalf("poke line = %q, want %q (zero-payload)", line, "data:")
	}
}

func TestHandler_HeartbeatFlows(t *testing.T) {
	ts, token, _ := enrolled(t)
	n := NewNotifier()
	mux := http.NewServeMux()
	NewHandler(n, ts).WithHeartbeatInterval(20 * time.Millisecond).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := openStream(t, srv.URL, token)
	defer resp.Body.Close()
	// No Notify at all — the first line on an idle stream must be the
	// contentless keep-alive comment.
	if line := readLine(t, bufio.NewReader(resp.Body)); line != ":hb" {
		t.Fatalf("idle line = %q, want %q", line, ":hb")
	}
}

func TestHandler_SubscriberCap429(t *testing.T) {
	ts, token, _ := enrolled(t)
	n := NewNotifier().WithMaxSubscribers(1)
	mux := http.NewServeMux()
	NewHandler(n, ts).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	first := openStream(t, srv.URL, token)
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first stream status %d, want 200", first.StatusCode)
	}
	second := openStream(t, srv.URL, token)
	defer second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second stream status %d, want 429", second.StatusCode)
	}
}

func TestHandler_RateLimited429(t *testing.T) {
	ts, token, _ := enrolled(t)
	n := NewNotifier()
	mux := http.NewServeMux()
	// Burst 1, refill 0: the first connection attempt spends the only token.
	NewHandler(n, ts).WithPolicy(gcquota.NewRateLimiter(1, 0)).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	first := openStream(t, srv.URL, token)
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first stream status %d, want 200", first.StatusCode)
	}
	second := openStream(t, srv.URL, token)
	defer second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("rate-limited stream status %d, want 429", second.StatusCode)
	}
}

func TestHandler_Unauthorized401(t *testing.T) {
	ts, _, _ := enrolled(t)
	n := NewNotifier()
	mux := http.NewServeMux()
	NewHandler(n, ts).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := openStream(t, srv.URL, strings.Repeat("ff", 32)) // unknown token
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
}
