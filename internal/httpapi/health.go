// SPDX-License-Identifier: AGPL-3.0-or-later

package httpapi

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// healthz is a liveness probe. It returns a static body with NO wall-clock
// timestamp and NO IP/user data (AS6/AS14). Operational observability is built on
// per-account counters elsewhere, never on a time- or IP-bearing health surface.
func healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// HealthCheckProbe performs a loopback GET of /healthz and returns a process
// exit code (0 = healthy, 1 = unhealthy). It backs the `myne-server healthcheck`
// subcommand wired into the container HEALTHCHECK — the distroless runtime image
// ships no shell or curl, so the binary probes itself. addr is the server's
// listen address (e.g. ":8080"); only its port is used, dialed over 127.0.0.1.
func HealthCheckProbe(addr string) int {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || port == "" || port == "0" {
		// Empty/unset → the server's own default; ":0" (ephemeral, E2E only) is
		// not a fixed target a sidecar probe can reach.
		port = "8080"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
