// SPDX-License-Identifier: AGPL-3.0

package httpapi

import "net/http"

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
