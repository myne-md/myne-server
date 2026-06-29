// SPDX-License-Identifier: AGPL-3.0

package httpapi

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/myne-md/myne-server/internal/auth"
)

func TestHealthz_OKNoTimestamp(t *testing.T) {
	srv := httptest.NewServer(NewRouter(auth.DenyAll{}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) != `{"status":"ok"}` {
		t.Fatalf("unexpected body %q", body)
	}
	// No wall-clock timestamp leaked into the response body.
	for _, banned := range []string{"time", "timestamp", "date", "20"} {
		if strings.Contains(strings.ToLower(string(body)), banned) {
			t.Fatalf("health body looks like it leaks a timestamp (%q): %q", banned, body)
		}
	}
}

func TestHealthz_RejectsNonGET(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	NewRouter(auth.DenyAll{}).ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz = %d, want 405", rr.Code)
	}
}

// TestNoIP_DiscardsSourceIP verifies the no-IP middleware strips IP-bearing
// headers and r.RemoteAddr before any handler can read or log them (C4/AS14).
func TestNoIP_DiscardsSourceIP(t *testing.T) {
	var seenXFF, seenUA, seenRemote string
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenXFF = r.Header.Get("X-Forwarded-For")
		seenUA = r.Header.Get("User-Agent")
		seenRemote = r.RemoteAddr
		w.WriteHeader(http.StatusOK)
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Real-Ip", "203.0.113.7")
	req.Header.Set("Forwarded", "for=203.0.113.7")
	req.Header.Set("User-Agent", "snoopy/1.0")
	req.RemoteAddr = "203.0.113.7:5555"

	noIP(probe).ServeHTTP(rr, req)

	if seenXFF != "" {
		t.Errorf("X-Forwarded-For reached handler: %q", seenXFF)
	}
	if seenUA != "" {
		t.Errorf("User-Agent reached handler: %q", seenUA)
	}
	if seenRemote != "" {
		t.Errorf("RemoteAddr reached handler: %q", seenRemote)
	}
}

// --- MYND-428 task 1: surface the bound port on :0 ---

func TestBoundPort_ResolvesEphemeralPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen :0: %v", err)
	}
	defer ln.Close()

	port := boundPort(ln)
	if port <= 0 {
		t.Fatalf("boundPort returned %d, want a resolved ephemeral port > 0", port)
	}
	if got := ln.Addr().(*net.TCPAddr).Port; got != port {
		t.Fatalf("boundPort = %d, listener addr port = %d", port, got)
	}
}

func TestSurfaceBoundAddr_WritesPortfile(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen :0: %v", err)
	}
	defer ln.Close()

	pf := filepath.Join(t.TempDir(), "port")
	t.Setenv("MYNE_SERVER_PORTFILE", pf)
	surfaceBoundAddr(ln)

	raw, err := os.ReadFile(pf)
	if err != nil {
		t.Fatalf("read portfile: %v", err)
	}
	got, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("portfile content %q not an int: %v", raw, err)
	}
	if got != boundPort(ln) {
		t.Fatalf("portfile port %d != resolved port %d", got, boundPort(ln))
	}
}

func TestRun_BindsZeroAndServesHealthz(t *testing.T) {
	pf := filepath.Join(t.TempDir(), "port")
	t.Setenv("MYNE_SERVER_PORTFILE", pf)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, "127.0.0.1:0") }()

	// Wait for the portfile to appear (race-free port discovery).
	var port int
	for i := 0; i < 200; i++ {
		if raw, err := os.ReadFile(pf); err == nil {
			if p, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && p > 0 {
				port = p
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if port == 0 {
		cancel()
		t.Fatalf("server did not surface a bound port via the portfile")
	}

	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/healthz")
	if err != nil {
		cancel()
		t.Fatalf("GET /healthz on resolved port: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}
