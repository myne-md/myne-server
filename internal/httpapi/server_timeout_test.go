// SPDX-License-Identifier: AGPL-3.0-or-later

package httpapi

// Regression guard for the connection-level timeout hardening. Go's http.Server
// defaults leave ReadHeaderTimeout and IdleTimeout unset, which exposes the listener
// to slowloris / idle-connection exhaustion — a real hole for a TB5 self-hoster
// fronting the server with an untuned proxy. newHTTPServer must keep these set; this
// pins it so a future change that drops them fails CI rather than silently regressing.

import (
	"net/http"
	"testing"
)

func TestNewHTTPServer_HardenedTimeouts(t *testing.T) {
	srv := newHTTPServer(http.NewServeMux())

	if srv.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout unset — slowloris (gosec G112) exposure")
	}
	if srv.IdleTimeout <= 0 {
		t.Error("IdleTimeout unset — idle keep-alive connections unbounded")
	}
	if srv.ReadHeaderTimeout != readHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, readHeaderTimeout)
	}
	if srv.IdleTimeout != idleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", srv.IdleTimeout, idleTimeout)
	}
	// ReadTimeout / WriteTimeout are intentionally unset (a wall-clock cap would
	// truncate a legitimate slow 64 MiB blob transfer). Assert the deliberate choice
	// so it reads as intentional, not forgotten.
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Errorf("ReadTimeout/WriteTimeout set (%v/%v) — would truncate large blob transfers",
			srv.ReadTimeout, srv.WriteTimeout)
	}
}
