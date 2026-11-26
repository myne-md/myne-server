// SPDX-License-Identifier: AGPL-3.0-only

package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAccessLog_NoIPField: the structured access log emits method/path/status and
// NEVER a client IP — even when the request carries a spoofed RemoteAddr and XFF,
// and even though accessLog sits behind noIP (which blanks RemoteAddr).
func TestAccessLog_NoIPField(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	spoof := "198.51.100.9"
	// noIP(accessLog(...)) — the real chain order: noIP outermost.
	h := noIP(accessLog(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Inside the chain: noIP has blanked RemoteAddr, so a logger here sees no IP.
		if r.RemoteAddr != "" {
			t.Errorf("RemoteAddr not blanked inside noIP: %q", r.RemoteAddr)
		}
		w.WriteHeader(http.StatusTeapot)
	})))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = spoof + ":4444"
	req.Header.Set("X-Forwarded-For", spoof)
	req.Header.Set("X-Real-Ip", spoof)
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if out == "" {
		t.Fatal("access log produced no output")
	}
	if strings.Contains(out, spoof) {
		t.Fatalf("client IP %q leaked into the access log: %s", spoof, out)
	}
	// The structured line carries the useful fields, no IP.
	for _, want := range []string{`"method":"GET"`, `"path":"/healthz"`, `"status":418`} {
		if !strings.Contains(out, want) {
			t.Errorf("access log missing %q: %s", want, out)
		}
	}
	// No IP-bearing keys in the schema.
	for _, forbidden := range []string{"remote_addr", "remoteAddr", "ip", "forwarded", "client_ip"} {
		if strings.Contains(strings.ToLower(out), forbidden) {
			t.Fatalf("access log schema contains IP-bearing key %q: %s", forbidden, out)
		}
	}
}

// TestAccessLog_ForwardsFlusher: the statusWriter wrapper must forward
// http.Flusher — the SSE poke handler type-asserts the writer and fails closed
// (500) on a non-flushable one, so a wrapper that hides Flusher silently 500s
// every /sync/poke that passes through the full middleware chain. Regression
// for exactly that (found by the live end-to-end poke test).
func TestAccessLog_ForwardsFlusher(t *testing.T) {
	var sawFlusher bool
	h := noIP(accessLog(slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, sawFlusher = w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
		})))
	// httptest.NewRecorder implements http.Flusher, mirroring the real server's
	// ResponseWriter; the wrapper must not hide it.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/sync/poke", nil))
	if !sawFlusher {
		t.Fatal("statusWriter hides http.Flusher from handlers (breaks the SSE poke stream)")
	}
}
