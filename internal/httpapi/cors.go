// SPDX-License-Identifier: AGPL-3.0-only

package httpapi

import (
	"net/http"
	"strings"
)

// CORS for the Phase 3 web client (main repo `phase3-web-client` task 34).
//
// Until now every client was native and no browser ever issued a preflight, so
// the server answered none. A browser client changes that: the page runs on its
// own origin (`decisions.md` 2026-07-26 — the web app gets a dedicated origin
// precisely because OPFS is origin-scoped), and every call it makes to the sync
// origin is cross-origin by construction.
//
// The policy is deliberately narrow, because this is the one boundary a hostile
// page attacks from:
//
//   - **Exact-origin allowlist, never `*`.** A wildcard would let any page on
//     the internet issue authenticated requests on the user's behalf if it ever
//     obtained a token, and `*` is incompatible with credentialed requests
//     anyway. The reflected value is always an origin the operator listed.
//   - **Empty list = off = today's behaviour.** A server that no browser talks
//     to answers no CORS headers at all, so enabling the web client is an
//     explicit operator action rather than a default that quietly widens the
//     edge.
//   - **Applies to every route the browser reaches, including the pre-auth
//     ones.** `POST /auth/scram/init` carries a JSON body, so it is not a
//     CORS-simple request and needs a preflight; a policy scoped to "authed
//     routes" would leave the browser's *first* call unanswered and auth would
//     fail before a token existed. That is also why this is outermost
//     middleware rather than per-handler: the server has no auth-middleware
//     layer — four packages register onto one root `ServeMux` and each does its
//     own inline token check — so there is no "authed routes" object to wrap.
//   - **Inside `noIP`, never outside it.** `noIP` blanks `RemoteAddr` and the
//     IP-bearing headers before anything reads them, and it stays the outermost
//     layer (C4/AS14). CORS sits directly beneath it.
//
// `Access-Control-Expose-Headers` is load-bearing rather than cosmetic: none of
// `X-Uploaded-Length`, `X-Complete`, `Content-Range` or `Accept-Ranges` is
// CORS-safelisted, so without it a cross-origin reader sees them as **absent**.
// The resumable-upload probe would read "0 bytes uploaded" for a
// half-transferred attachment and restart from zero, and a Range GET would look
// like an unranged one. Both fail silently, which is the worst shape.
//
// The operator knob is `MYNE_ALLOWED_ORIGINS` (comma-separated). It is a
// per-deployment value by necessity — the hosted app origin and every
// self-hoster's own origin are different strings — which is why it is
// configured, not compiled in (TB5: hosted and self-hosted share one protocol
// and one security model).

// corsPolicy holds the parsed allowlist. A nil/empty policy is a no-op.
type corsPolicy struct {
	origins map[string]struct{}
}

// Request headers the browser is permitted to send. `Authorization` carries the
// per-device token, `Content-Type` the JSON bodies, `Range` the resumable
// attachment reads.
const corsAllowHeaders = "Authorization, Content-Type, Range"

// Response headers the browser is permitted to READ. Everything here is
// non-safelisted, so omitting a name makes that header invisible cross-origin.
const corsExposeHeaders = "X-Uploaded-Length, X-Complete, Content-Range, Accept-Ranges"

// Methods any route in this server uses. Enumerated rather than reflected from
// the request so a preflight for an unimplemented method is refused here.
const corsAllowMethods = "GET, HEAD, POST, PUT, OPTIONS"

// How long a browser may cache a preflight result. Ten minutes: long enough that
// a working session is not re-preflighting constantly, short enough that an
// operator removing an origin sees it take effect without telling users to
// restart their browser.
const corsMaxAge = "600"

// parseAllowedOrigins turns the comma-separated env value into a policy.
// Entries are trimmed and compared exactly — no scheme-insensitivity, no
// trailing-slash tolerance, no subdomain wildcards. An origin is a precise
// string in the browser's model, and a "helpful" normalisation here is how an
// allowlist ends up matching something the operator did not intend.
func parseAllowedOrigins(raw string) *corsPolicy {
	origins := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		o := strings.TrimSpace(part)
		if o == "" || o == "*" {
			// `*` is refused rather than honoured: it cannot be combined with
			// credentials, and accepting it would turn a typo into an open edge.
			continue
		}
		origins[o] = struct{}{}
	}
	if len(origins) == 0 {
		return nil
	}
	return &corsPolicy{origins: origins}
}

// allows reports whether `origin` is on the allowlist.
func (p *corsPolicy) allows(origin string) bool {
	if p == nil || origin == "" {
		return false
	}
	_, ok := p.origins[origin]
	return ok
}

// cors wraps `next` with the policy. A nil policy returns `next` unchanged, so
// a deployment with no browser client carries no CORS code path at all.
func cors(p *corsPolicy, next http.Handler) http.Handler {
	if p == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := p.allows(origin)

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			// The reflected origin varies per request, so caches must key on it.
			// Without this a shared cache can serve one origin's response to
			// another.
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Expose-Headers", corsExposeHeaders)
		}

		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			// Preflight. Answer here and never reach a handler: the route may
			// not implement OPTIONS at all, and a 404/405 to a preflight reads
			// to the browser as "denied" with no explanation.
			if !allowed {
				// A disallowed origin gets a bare 403 with NO CORS headers,
				// which is what makes the browser block the real request.
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")
			w.Header().Set("Access-Control-Allow-Methods", corsAllowMethods)
			w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
			w.Header().Set("Access-Control-Max-Age", corsMaxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Non-preflight requests proceed regardless. A disallowed origin simply
		// gets no `Access-Control-Allow-Origin`, and the browser refuses to hand
		// the response to the page — which is the correct enforcement point.
		// Refusing server-side instead would break every non-browser client,
		// none of which sends an `Origin` header.
		next.ServeHTTP(w, r)
	})
}
