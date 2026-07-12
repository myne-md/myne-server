// SPDX-License-Identifier: AGPL-3.0

package httpapi

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// Metrics is the server's aggregate-only observability surface (MYND-440, SYNC-24).
//
// LOAD-BEARING PRIVACY INVARIANT: every exported series is an AGGREGATE across all
// accounts — there is NO field, label, or method here that scales with the
// account/vault/device population. Per-account counters live elsewhere (enforcement
// only, e.g. the rate-limiter) and are NEVER exported as a labelled time-series: an
// `account_number_hash`-labelled metric would re-create a per-account behavioural
// timeline (§6 review-stopper) and leak independent of the zero-knowledge content.
// Because this is a hand-rolled fixed counter set (not a dynamic-label library),
// there is no mechanism to add such a label without writing new code — the invariant
// is STRUCTURAL, not a convention a reviewer must police.
//
// Emitted by a stdlib Prometheus-text handler (zero dependency — no client_golang /
// OTel, which would be the server's first non-stdlib dep, TB9). Bound to a SEPARATE
// localhost/auth-gated listener, never the public Caddy edge.
type Metrics struct {
	requestsTotal                 atomic.Uint64
	blobsStoredTotal              atomic.Uint64
	bytesStoredTotal              atomic.Uint64
	tombstonesReclaimedTotal      atomic.Uint64
	attachmentsStoredTotal        atomic.Uint64
	attachmentBytesStoredTotal    atomic.Uint64
	attachmentsReclaimedTotal     atomic.Uint64
	attachmentBytesReclaimedTotal atomic.Uint64
}

// NewMetrics returns a zeroed metrics registry.
func NewMetrics() *Metrics { return &Metrics{} }

// IncRequest counts one served request (no method/path/IP label — aggregate only).
func (m *Metrics) IncRequest() { m.requestsTotal.Add(1) }

// ObserveBlobStored records one stored blob of n bytes (fed by the push path).
func (m *Metrics) ObserveBlobStored(n int) {
	m.blobsStoredTotal.Add(1)
	if n > 0 {
		m.bytesStoredTotal.Add(uint64(n))
	}
}

// IncTombstoneReclaimed records one L2-reclaimed tombstone (fed by the GC scheduler).
func (m *Metrics) IncTombstoneReclaimed() { m.tombstonesReclaimedTotal.Add(1) }

// ObserveAttachmentStored records one COMPLETED attachment upload of n bytes
// (fed by the /attachments PUT completion, MYND-468).
func (m *Metrics) ObserveAttachmentStored(n int) {
	m.attachmentsStoredTotal.Add(1)
	if n > 0 {
		m.attachmentBytesStoredTotal.Add(uint64(n))
	}
}

// ObserveAttachmentReclaimed records one reclaimed attachment body of n bytes
// (fed by the horizon-GC attachment bridge, MYND-468).
func (m *Metrics) ObserveAttachmentReclaimed(n uint64) {
	m.attachmentsReclaimedTotal.Add(1)
	m.attachmentBytesReclaimedTotal.Add(n)
}

// middleware counts requests around the next handler. It is placed INSIDE noIP so it
// never observes a client IP (noIP has already blanked RemoteAddr / stripped headers).
func (m *Metrics) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.IncRequest()
		next.ServeHTTP(w, r)
	})
}

// handler emits the fixed aggregate set in Prometheus exposition text. No labels.
func (m *Metrics) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	// A fixed, label-free counter set — aggregate across all accounts.
	fmt.Fprintf(w, "# HELP myne_requests_total Total requests served (aggregate; no per-identity label).\n")
	fmt.Fprintf(w, "# TYPE myne_requests_total counter\n")
	fmt.Fprintf(w, "myne_requests_total %d\n", m.requestsTotal.Load())
	fmt.Fprintf(w, "# HELP myne_blobs_stored_total Total blobs stored (aggregate).\n")
	fmt.Fprintf(w, "# TYPE myne_blobs_stored_total counter\n")
	fmt.Fprintf(w, "myne_blobs_stored_total %d\n", m.blobsStoredTotal.Load())
	fmt.Fprintf(w, "# HELP myne_bytes_stored_total Total ciphertext bytes stored (aggregate).\n")
	fmt.Fprintf(w, "# TYPE myne_bytes_stored_total counter\n")
	fmt.Fprintf(w, "myne_bytes_stored_total %d\n", m.bytesStoredTotal.Load())
	fmt.Fprintf(w, "# HELP myne_tombstones_reclaimed_total Total tombstones L2-reclaimed by GC (aggregate).\n")
	fmt.Fprintf(w, "# TYPE myne_tombstones_reclaimed_total counter\n")
	fmt.Fprintf(w, "myne_tombstones_reclaimed_total %d\n", m.tombstonesReclaimedTotal.Load())
	fmt.Fprintf(w, "# HELP myne_attachments_stored_total Total completed attachment uploads (aggregate).\n")
	fmt.Fprintf(w, "# TYPE myne_attachments_stored_total counter\n")
	fmt.Fprintf(w, "myne_attachments_stored_total %d\n", m.attachmentsStoredTotal.Load())
	fmt.Fprintf(w, "# HELP myne_attachment_bytes_stored_total Total attachment ciphertext bytes stored (aggregate).\n")
	fmt.Fprintf(w, "# TYPE myne_attachment_bytes_stored_total counter\n")
	fmt.Fprintf(w, "myne_attachment_bytes_stored_total %d\n", m.attachmentBytesStoredTotal.Load())
	fmt.Fprintf(w, "# HELP myne_attachments_reclaimed_total Total attachment bodies reclaimed by GC (aggregate).\n")
	fmt.Fprintf(w, "# TYPE myne_attachments_reclaimed_total counter\n")
	fmt.Fprintf(w, "myne_attachments_reclaimed_total %d\n", m.attachmentsReclaimedTotal.Load())
	fmt.Fprintf(w, "# HELP myne_attachment_bytes_reclaimed_total Total attachment ciphertext bytes reclaimed (aggregate).\n")
	fmt.Fprintf(w, "# TYPE myne_attachment_bytes_reclaimed_total counter\n")
	fmt.Fprintf(w, "myne_attachment_bytes_reclaimed_total %d\n", m.attachmentBytesReclaimedTotal.Load())
}

// MetricsHandler returns the /metrics http.Handler. The CALLER binds it to a separate
// localhost/auth-gated listener — it is deliberately NOT registered on the public mux.
func (m *Metrics) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", m.handler)
	return mux
}
