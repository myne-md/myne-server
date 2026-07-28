// SPDX-License-Identifier: AGPL-3.0

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The routes a browser actually reaches. Enumerated as data rather than
// exercised one-by-one because the failure this guards against is "the policy
// was scoped to the authed routes and the browser's FIRST call — a pre-auth
// one with a JSON body, so preflighted — went unanswered".
var browserRoutes = []struct {
	method  string
	path    string
	preAuth bool
}{
	{"POST", "/auth/register", true},
	{"POST", "/auth/scram/init", true},
	{"POST", "/auth/scram/final", true},
	{"GET", "/vault.meta", true},
	{"GET", "/auth/devices", false},
	{"POST", "/auth/devices/approve", false},
	{"POST", "/auth/devices/revoke", false},
	{"POST", "/sync/push", false},
	{"POST", "/sync/pull", false},
	{"GET", "/sync/blob", false},
	{"GET", "/sync/poke", false},
	{"GET", "/account/status", false},
	{"HEAD", "/attachments/aa", false},
	{"GET", "/attachments/aa", false},
	{"PUT", "/attachments/aa", false},
}

const appOrigin = "https://app.example.com"
const selfHostOrigin = "https://notes.example.org"

// corsHandler wraps a trivial terminal handler, mirroring the production chain
// order (cors inside noIP) closely enough to test the policy itself.
func corsHandler(t *testing.T, allowed string) http.Handler {
	t.Helper()
	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Uploaded-Length", "7")
		w.WriteHeader(http.StatusOK)
	})
	return noIP(cors(parseAllowedOrigins(allowed), terminal))
}

func preflight(t *testing.T, h http.Handler, method, path, origin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodOptions, path, nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", method)
	req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestPreflightAnsweredOnEveryBrowserRoute(t *testing.T) {
	h := corsHandler(t, appOrigin)
	for _, r := range browserRoutes {
		rr := preflight(t, h, r.method, r.path, appOrigin)
		if rr.Code != http.StatusNoContent {
			t.Errorf("%s %s: preflight status = %d, want 204 (preAuth=%v)", r.method, r.path, rr.Code, r.preAuth)
		}
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != appOrigin {
			t.Errorf("%s %s: Allow-Origin = %q, want %q", r.method, r.path, got, appOrigin)
		}
		if !strings.Contains(rr.Header().Get("Access-Control-Allow-Methods"), r.method) {
			t.Errorf("%s %s: Allow-Methods = %q, missing %s", r.method, r.path, rr.Header().Get("Access-Control-Allow-Methods"), r.method)
		}
	}
}

func TestAllowHeadersCoversWhatTheBrowserSends(t *testing.T) {
	rr := preflight(t, corsHandler(t, appOrigin), "PUT", "/attachments/aa", appOrigin)
	got := rr.Header().Get("Access-Control-Allow-Headers")
	for _, want := range []string{"Authorization", "Content-Type", "Range"} {
		if !strings.Contains(got, want) {
			t.Errorf("Allow-Headers = %q, missing %s", got, want)
		}
	}
}

// Non-safelisted response headers read as ABSENT cross-origin unless exposed.
// Without this the resumable-upload probe sees "0 bytes uploaded" for a
// half-transferred attachment and restarts from zero — a silent misbehaviour,
// not an error.
func TestExposeHeadersCoversTheResumableAndRangeSurface(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/attachments/aa", nil)
	req.Header.Set("Origin", appOrigin)
	rr := httptest.NewRecorder()
	corsHandler(t, appOrigin).ServeHTTP(rr, req)

	got := rr.Header().Get("Access-Control-Expose-Headers")
	for _, want := range []string{"X-Uploaded-Length", "X-Complete", "Content-Range", "Accept-Ranges"} {
		if !strings.Contains(got, want) {
			t.Errorf("Expose-Headers = %q, missing %s", got, want)
		}
	}
}

func TestDisallowedOriginGetsNoAllowOriginAndAPreflight403(t *testing.T) {
	h := corsHandler(t, appOrigin)

	rr := preflight(t, h, "POST", "/sync/push", "https://evil.example")
	if rr.Code != http.StatusForbidden {
		t.Errorf("preflight from a disallowed origin: status = %d, want 403", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("preflight from a disallowed origin: Allow-Origin = %q, want empty", got)
	}

	// A non-preflight request still runs (non-browser clients send no Origin and
	// must not be affected), but carries no Allow-Origin, so the browser refuses
	// to hand the response to the page.
	req := httptest.NewRequest(http.MethodPost, "/sync/push", nil)
	req.Header.Set("Origin", "https://evil.example")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req)
	if got := rr2.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("request from a disallowed origin: Allow-Origin = %q, want empty", got)
	}
	if rr2.Code != http.StatusOK {
		t.Errorf("request from a disallowed origin should still reach the handler; status = %d", rr2.Code)
	}
}

// The wildcard is refused, not honoured: `*` cannot be combined with
// credentials, and accepting it would turn an operator typo into an open edge.
func TestWildcardIsRefusedNotHonoured(t *testing.T) {
	if p := parseAllowedOrigins("*"); p != nil {
		t.Fatalf("parseAllowedOrigins(%q) = %v, want nil (wildcard refused)", "*", p)
	}
	h := corsHandler(t, "*")
	rr := preflight(t, h, "POST", "/sync/push", appOrigin)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("wildcard config: Allow-Origin = %q, want empty (policy off)", got)
	}
}

// Empty = off = the pre-web behaviour. A native-only deployment must be
// byte-identical to what it was before CORS existed.
func TestEmptyAllowlistIsAPureNoOp(t *testing.T) {
	if p := parseAllowedOrigins(""); p != nil {
		t.Fatalf("parseAllowedOrigins(\"\") = %v, want nil", p)
	}
	req := httptest.NewRequest(http.MethodPost, "/sync/push", nil)
	req.Header.Set("Origin", appOrigin)
	rr := httptest.NewRecorder()
	corsHandler(t, "").ServeHTTP(rr, req)
	for _, h := range []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Credentials",
		"Access-Control-Expose-Headers",
		"Vary",
	} {
		if got := rr.Header().Get(h); got != "" {
			t.Errorf("CORS off: %s = %q, want empty", h, got)
		}
	}
}

// Self-hosters configure their own origin; the hosted app origin is not special
// (TB5 — one protocol, one model, different operators).
func TestMultipleOriginsAndSelfHostOrigin(t *testing.T) {
	h := corsHandler(t, appOrigin+", "+selfHostOrigin)
	for _, o := range []string{appOrigin, selfHostOrigin} {
		rr := preflight(t, h, "POST", "/sync/pull", o)
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != o {
			t.Errorf("origin %q: Allow-Origin = %q, want the same", o, got)
		}
	}
	rr := preflight(t, h, "POST", "/sync/pull", "https://app.example.com.evil.example")
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("suffix-lookalike origin was allowed: %q", got)
	}
}

// A reflected Allow-Origin varies per request, so a shared cache must key on
// Origin or it can serve one origin's response to another.
func TestVaryOnOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/account/status", nil)
	req.Header.Set("Origin", appOrigin)
	rr := httptest.NewRecorder()
	corsHandler(t, appOrigin).ServeHTTP(rr, req)
	if !strings.Contains(rr.Header().Get("Vary"), "Origin") {
		t.Errorf("Vary = %q, want it to contain Origin", rr.Header().Get("Vary"))
	}
}

// A request with no Origin header is a native client. It must be untouched —
// desktop and mobile never send one, and every one of them predates this policy.
func TestNativeClientWithNoOriginIsUnaffected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/sync/push", nil)
	rr := httptest.NewRecorder()
	corsHandler(t, appOrigin).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("no-Origin request: status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("no-Origin request: Allow-Origin = %q, want empty", got)
	}
}

// `noIP` must remain the outermost layer: CORS reflects a header the browser
// sends, and must never be positioned where it could observe a client IP.
func TestCorsSitsInsideNoIP(t *testing.T) {
	var sawRemoteAddr, sawXFF string
	terminal := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		sawRemoteAddr, sawXFF = r.RemoteAddr, r.Header.Get("X-Forwarded-For")
	})
	h := noIP(cors(parseAllowedOrigins(appOrigin), terminal))

	req := httptest.NewRequest(http.MethodGet, "/account/status", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("Origin", appOrigin)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if sawRemoteAddr != "" || sawXFF != "" {
		t.Errorf("IP-bearing data survived the chain: RemoteAddr=%q XFF=%q", sawRemoteAddr, sawXFF)
	}
}
