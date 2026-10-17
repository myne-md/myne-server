// SPDX-License-Identifier: AGPL-3.0

package httpapi

import (
	"log/slog"
	"net/http"
)

// noIP enforces the no-persistent-IP-logging discipline (C4/AS14): it ACTIVELY
// discards source-IP-bearing data before any handler or log can read it. The
// server's operational logging works on per-account counters, never source IPs;
// this middleware guarantees IP-bearing headers (and r.RemoteAddr) never reach
// handler code or a log line by accident. Active discard, not passive non-logging.
func noIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("X-Forwarded-For")
		r.Header.Del("X-Real-Ip")
		r.Header.Del("Forwarded")
		r.Header.Del("User-Agent")
		r.RemoteAddr = ""
		next.ServeHTTP(w, r)
	})
}

// recoverPanic turns a panicking handler into a bounded, IP-free log line and a
// 500, instead of letting it reach `net/http`'s own recovery.
//
// The stdlib's recovery is what makes a panic a privacy problem rather than
// merely an availability one: it logs `http: panic serving %v` with
// `http.conn.remoteAddr` — the address captured at accept time — which no
// middleware can blank, because it is not the request's `RemoteAddr` that
// [noIP] clears. `newHTTPServer` discards `ErrorLog` so that line reaches no
// sink; this middleware is the other half, so the panic is still observable.
//
// What is logged is deliberately narrow: the method and the route path, and
// nothing else. Not the panic value (it can carry request-derived state), not a
// stack (frames can carry arguments), not an account. That keeps it inside the
// ALLOW list in `src-tauri/AGENTS.md` "Secret-handling logging discipline",
// which this server follows too.
//
// The 500 is written only if the handler had not already written a header —
// after a partial response the connection is broken by the panic and there is
// no valid status left to send.
func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// http.ErrAbortHandler is the documented way for a handler to
				// abandon a response deliberately; it is not an error and the
				// stdlib does not log it either.
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				slog.Error("handler_panic", "method", r.Method, "path", r.URL.Path)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
