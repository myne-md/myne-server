// SPDX-License-Identifier: AGPL-3.0

package syncapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/gcquota"
	"github.com/myne-md/myne-server/internal/store"
)

// The pre-auth GET /vault.meta bootstrap is gated by the global limiter: once its
// burst is drained the route returns 429 (session-less, so a per-account key is
// impossible — the account is an attacker-supplied query value).
func TestMetaGet_PreAuthRateLimited429(t *testing.T) {
	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	mux := http.NewServeMux()
	New(st, ts).WithPreAuthLimiter(gcquota.NewGlobalLimiter(1, 0)).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	acct := strings.Repeat("42", 16)
	// First (unauthenticated) GET consumes the single token → not 429 (404: no meta).
	if resp, _ := do(t, srv, http.MethodGet, "/vault.meta?account="+acct, "", ""); resp.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("first meta GET should not be 429")
	}
	// Second GET → bucket empty → 429.
	if resp, _ := do(t, srv, http.MethodGet, "/vault.meta?account="+acct, "", ""); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second meta GET status %d, want 429", resp.StatusCode)
	}
}
