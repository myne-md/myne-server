// SPDX-License-Identifier: AGPL-3.0

package httpapi

import (
	"net/http"
	"sync/atomic"
)

// Readiness is the server's readiness gate (MYND-440). It is distinct from the
// liveness probe (/healthz, "the process is up") — readiness reports whether the
// server is actually ready to serve traffic: store initialized + migrations
// complete (set ready), and not-ready once graceful shutdown begins (so an
// orchestrator stops routing before connections drain). Like /healthz it carries
// NO wall-clock timestamp and NO IP/user data (AS6/AS14).
type Readiness struct {
	ready atomic.Bool
}

// NewReadiness returns a gate that starts NOT ready (until SetReady is called once
// store init + migrations have completed).
func NewReadiness() *Readiness { return &Readiness{} }

// SetReady marks the server ready (after store init + migrations, before listen).
func (r *Readiness) SetReady() { r.ready.Store(true) }

// SetNotReady marks the server not ready (at the start of graceful shutdown).
func (r *Readiness) SetNotReady() { r.ready.Store(false) }

// handler is the /readyz probe: 200 + {"status":"ready"} when ready, else 503.
func (r *Readiness) handler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !r.ready.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"not-ready"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}
