// SPDX-License-Identifier: AGPL-3.0

package httpapi

import (
	"log/slog"
	"net/http"
)

// accessLog is a structured (slog) access-log middleware (MYND-440, SYNC-24). Its
// schema has NO IP field at all: it logs method, path, and status — never
// RemoteAddr, X-Forwarded-For, or any per-account identifier. It MUST sit INSIDE
// noIP in the chain so that even the raw request it sees has a blanked RemoteAddr
// and stripped IP headers (defense in depth). It writes one line per request with
// no retained per-account behavioural timeline (AS6/AS14/C4).
func accessLog(logger *slog.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		// Deliberately no IP / RemoteAddr / forwarded-for / account field.
		logger.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.status)
	})
}

// statusWriter captures the response status for the access log.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush forwards http.Flusher so the SSE poke stream can flush per event
// through the access-log wrapper. Without this, the embedded-interface
// wrapper hides the underlying Flusher from the poke handler's type
// assertion and every /sync/poke through the full middleware chain 500s
// (the handler fails closed on a non-flushable writer).
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
