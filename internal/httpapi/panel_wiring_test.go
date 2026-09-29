// SPDX-License-Identifier: AGPL-3.0

package httpapi

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/console"
	"github.com/myne-md/myne-server/internal/panel"
)

// The panel gets the SAME hardened server constructor as the public edge, which is
// what discards the standard library's connection-level error log. Those two stdlib
// sites (a handler panic and a failed TLS handshake) write the peer address, and the
// TLS one never passes through any middleware at all, so no handler-level care could
// have covered it. The panel listener can sit on a network, so this is the one place
// it could otherwise leak an IP nobody asked it to record.
func TestPanelServer_DiscardsStdlibErrorLogAndSetsTimeouts(t *testing.T) {
	srv := newHTTPServer(panel.New(console.NewProjection(nil, nil, nil, nil, 0), "").Mux())

	if srv.ErrorLog == nil {
		t.Fatal("panel server has no ErrorLog: the standard library would default it to the log package, i.e. stderr, i.e. the container log stream")
	}
	if got := srv.ErrorLog.Writer(); got != io.Discard {
		t.Errorf("panel server ErrorLog writer = %v, want io.Discard: a peer address would reach the container log", got)
	}
	if srv.ReadHeaderTimeout == 0 {
		t.Error("panel server has no ReadHeaderTimeout")
	}
	if srv.IdleTimeout == 0 {
		t.Error("panel server has no IdleTimeout")
	}
}

// The panel's route table must be the read-only one, on the operator's TCP listener
// too. Spelled out here as well as in the panel package because this is the wiring
// that puts it on a network: a future refactor that hands the admin mux to the panel
// listener would pass the panel's own tests and expose every write route.
func TestPanelListener_ServesOnlyTheReadOnlyMux(t *testing.T) {
	h := panel.New(console.NewProjection(nil, nil, nil, nil, 0), "").Mux()

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		// The admin API's real enforcement paths, not path prefixes: those routes sit
		// one level under /admin/accounts/{hash}/, so a prefix-only test would report
		// green on a listener wired to the writable mux.
		for _, path := range []string{
			"/", "/panel.css",
			"/admin/accounts/0123456789abcdef0123456789abcdef/freeze",
			"/admin/accounts/0123456789abcdef0123456789abcdef/unfreeze",
			"/admin/accounts/0123456789abcdef0123456789abcdef/quota",
			"/admin/accounts/0123456789abcdef0123456789abcdef/max-devices",
			"/admin/accounts/0123456789abcdef0123456789abcdef",
		} {
			// 2xx is the failure band: it means a handler answered a write verb.
			if code := statusFor(h, method, path); code >= 200 && code < 300 {
				t.Errorf("%s %s answered %d on the panel listener: a write route is reachable", method, path, code)
			}
		}
	}
}

func statusFor(h http.Handler, method, path string) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code
}

// Both operator-only TCP listeners bind through ONE mechanism, and it warns once
// when the resolved address is reachable from the network rather than just this
// machine.
func TestListenInternal_WarnsOnceOnlyForANetworkAddress(t *testing.T) {
	cases := []struct {
		addr string
		warn bool
		what string
	}{
		{"127.0.0.1:0", false, "loopback IPv4 must stay silent"},
		{"[::1]:0", false, "loopback IPv6 must stay silent"},
		{"localhost:0", false, "the loopback name must stay silent"},
		{":0", true, "an empty host binds every interface and must warn"},
		{"0.0.0.0:0", true, "an explicit all-interfaces bind must warn"},
	}
	// Only addresses this machine can actually bind appear above. A documentation
	// range like 192.0.2.0/24 is non-loopback but NOT assignable, so asserting on it
	// through a real bind would test the network, not the rule. It is covered by
	// TestIsLoopbackAddr below, which is the right seam for a string classifier.

	for _, tc := range cases {
		var buf strings.Builder
		orig := log.Writer()
		log.SetOutput(&buf)
		log.SetFlags(0)

		ln, err := listenInternal("test surface", tc.addr)
		log.SetOutput(orig)

		if err != nil {
			t.Fatalf("listenInternal(%q): %v", tc.addr, err)
		}
		got := buf.String()
		ln.Close()

		if tc.warn {
			if got == "" {
				t.Errorf("listenInternal(%q) bound %s silently: %s", tc.addr, ln.Addr(), tc.what)
			}
			if n := strings.Count(got, "WARN"); n != 1 {
				t.Errorf("listenInternal(%q) produced %d WARN lines, want exactly 1: %q", tc.addr, n, got)
			}
			if !strings.Contains(got, ln.Addr().String()) {
				t.Errorf("listenInternal(%q) warning does not name the resolved address: %q", tc.addr, got)
			}
		} else if got != "" {
			t.Errorf("listenInternal(%q) warned on a loopback address: %s (%q)", tc.addr, tc.what, got)
		}
	}
}

// An empty address is not a bind at all: both operator surfaces are off by default and
// must report that without touching the network.
func TestListenInternal_EmptyIsDisabled(t *testing.T) {
	ln, err := listenInternal("test surface", "")
	if err != nil {
		t.Fatalf("listenInternal(\"\") = %v, want nil listener", err)
	}
	if ln != nil {
		ln.Close()
		t.Fatal("listenInternal(\"\") bound a listener")
	}
}

// A bind failure names the address, so an operator whose surface never came up has
// something to act on.
func TestListenInternal_FailureNamesTheAddress(t *testing.T) {
	bad := "127.0.0.1:not-a-port"
	_, err := listenInternal("test surface", bad)
	if err == nil {
		t.Fatal("listenInternal accepted a malformed address: a bind failure must fail startup")
	}
	if !strings.Contains(err.Error(), bad) {
		t.Errorf("bind error %q does not name the address %q", err, bad)
	}
}

// isLoopbackAddr is a pure classifier over a resolved host:port, so the LAN cases are
// testable without binding them. "Can this machine actually take this address" is a
// different question and belongs to a bind, not to this function.
func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080":   true,
		"127.0.0.53:9090":  true,
		"[::1]:8080":       true,
		"localhost:8080":   true,
		"":                 false, // an empty host binds every interface
		":8080":            false,
		"0.0.0.0:8080":     false,
		"[::]:8080":        false,
		"192.0.2.10:8080":  false,
		"10.0.0.5:8080":    false,
		"203.0.113.7:9000": false,
		"not-an-addr":      false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

// The panel's chain must include panic recovery, not only the discarded error log.
// §5.2 pairs the two: the stdlib's per-connection panic log carries the peer address,
// so discarding it without recovering trades a privacy leak for silence. Before this
// was named there was NO test that could fail if the middleware were dropped, which
// an injected removal proved.
func TestPanelChain_RecoversAPanicWithA500(t *testing.T) {
	panics := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })

	rec := httptest.NewRecorder()
	operatorPanelHandler(panics).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("a panicking panel handler answered %d, want 500: a panic must not break the connection silently", rec.Code)
	}
}

// A panic must not print a stack to the process's stderr either, since the discarded
// ErrorLog and the recovery are what keep the address out of the container's log.
func TestPanelChain_DoesNotSurfaceThePanicOnStderr(t *testing.T) {
	panics := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })

	var captured strings.Builder
	orig := log.Writer()
	log.SetOutput(&captured)
	defer log.SetOutput(orig)

	operatorPanelHandler(panics).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if strings.Contains(captured.String(), "boom") {
		t.Errorf("the panic value reached the process log, which the discarded error log exists to prevent:\n%s", captured.String())
	}
}
