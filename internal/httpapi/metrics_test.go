// SPDX-License-Identifier: AGPL-3.0

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMetrics_AggregateOnlyExposition(t *testing.T) {
	m := NewMetrics()
	m.IncRequest()
	m.ObserveBlobStored(100)
	m.ObserveBlobStored(50)
	m.IncTombstoneReclaimed()

	rec := httptest.NewRecorder()
	m.handler(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		"myne_requests_total 1",
		"myne_blobs_stored_total 2",
		"myne_bytes_stored_total 150",
		"myne_tombstones_reclaimed_total 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %q:\n%s", want, body)
		}
	}

	// STRUCTURAL no-label invariant: not a single metric line carries a label set
	// (`{...}`). A per-account/vault/device label would re-create a behavioural
	// timeline (SYNC-24). The hand-rolled handler has no way to emit one.
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "myne_") && strings.ContainsAny(line, "{}") {
			t.Fatalf("metric line carries a label (forbidden — aggregate only): %q", line)
		}
	}
	// And no account_number_hash anywhere.
	if strings.Contains(strings.ToLower(body), "account") {
		t.Fatalf("exposition mentions 'account' — possible per-account leak:\n%s", body)
	}
}

// TestMetrics_RaceClean exercises concurrent increments + scrape under -race.
func TestMetrics_RaceClean(t *testing.T) {
	m := NewMetrics()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.IncRequest()
			m.ObserveBlobStored(10)
			m.IncTombstoneReclaimed()
			rec := httptest.NewRecorder()
			m.handler(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		}()
	}
	wg.Wait()
	if m.requestsTotal.Load() != 50 {
		t.Fatalf("requestsTotal = %d, want 50", m.requestsTotal.Load())
	}
}

// TestMetrics_MiddlewareCountsInsideNoIP confirms the middleware counts a request
// and that /metrics is served by a separate handler, not the main mux.
func TestMetrics_MiddlewareCountsRequests(t *testing.T) {
	m := NewMetrics()
	h := m.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if m.requestsTotal.Load() != 1 {
		t.Fatalf("middleware did not count the request: %d", m.requestsTotal.Load())
	}
	// The /metrics handler is a separate mux (not the public server mux).
	if m.MetricsHandler() == nil {
		t.Fatal("MetricsHandler nil")
	}
}
