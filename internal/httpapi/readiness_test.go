// SPDX-License-Identifier: AGPL-3.0-only

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadiness_GatesOnState(t *testing.T) {
	r := NewReadiness()

	// Starts NOT ready → 503.
	rec := httptest.NewRecorder()
	r.handler(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("initial readiness = %d, want 503", rec.Code)
	}

	// After SetReady → 200.
	r.SetReady()
	rec = httptest.NewRecorder()
	r.handler(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ready") {
		t.Fatalf("ready body = %q, want a status", body)
	}
	// No timestamp/IP surface: the body is a static status only.
	if strings.ContainsAny(body, "0123456789") {
		t.Fatalf("readiness body contains digits (possible timestamp leak): %q", body)
	}

	// After SetNotReady (shutdown) → 503 again.
	r.SetNotReady()
	rec = httptest.NewRecorder()
	r.handler(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("post-shutdown readiness = %d, want 503", rec.Code)
	}
}
