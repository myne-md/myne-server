// SPDX-License-Identifier: AGPL-3.0

// Package poke is the change-notification layer (MYND-423). Polling (the pull
// endpoint) remains the fallback the server always serves; clients keep an SSE poke
// open while unlocked (sync-protocol §8.3 as amended — the fixed-interval polling
// baseline already discloses presence at poll granularity, so the continuous
// channel's marginal A13 delta was judged not worth a user-facing toggle). The poke
// is LITERALLY zero-payload: it carries no note-id, no version, no count, no cursor
// — only "something changed, come pull". The channel is session-bound (a spoofed
// poke is at worst low-severity DoS, but still must be authenticated), rate-limited
// per account (never IP, C4), capped per account, and heartbeat-keepalive'd so
// clients can detect a dead stream with a plain read timeout.
package poke

import (
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
)

// DefaultMaxSubscribersPerAccount bounds concurrent SSE streams per account — an
// OOM/fd bound, generous against the device-approval-gated device count.
const DefaultMaxSubscribersPerAccount = 8

// DefaultHeartbeatInterval is the SSE comment-line keep-alive cadence. The client's
// dead-connection read-timeout is calibrated to two missed heartbeats plus margin;
// changing this requires revisiting that client constant.
const DefaultHeartbeatInterval = 30 * time.Second

// RateLimiter gates connection attempts per account (nil = disabled). Satisfied by
// the same gcquota.RateLimiter the sync/attachment routes share — keyed on
// account_number_hash, never IP (C4).
type RateLimiter interface {
	Allow(account ids.AccountNumberHash) bool
}

// Notifier fans a contentless "changed" signal out to a vault's SSE subscribers.
type Notifier struct {
	mu     sync.Mutex
	subs   map[ids.AccountNumberHash]map[chan struct{}]struct{}
	maxPer int
}

// NewNotifier returns an empty notifier with the default per-account cap.
func NewNotifier() *Notifier {
	return &Notifier{
		subs:   make(map[ids.AccountNumberHash]map[chan struct{}]struct{}),
		maxPer: DefaultMaxSubscribersPerAccount,
	}
}

// WithMaxSubscribers overrides the per-account subscriber cap (tests).
func (n *Notifier) WithMaxSubscribers(max int) *Notifier {
	n.maxPer = max
	return n
}

// subscribe registers a listener; false when the account is at its cap (the caller
// maps that to 429 — same class as the token-bucket reject).
func (n *Notifier) subscribe(a ids.AccountNumberHash) (chan struct{}, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.subs[a] == nil {
		n.subs[a] = make(map[chan struct{}]struct{})
	}
	if len(n.subs[a]) >= n.maxPer {
		return nil, false
	}
	ch := make(chan struct{}, 1)
	n.subs[a][ch] = struct{}{}
	return ch, true
}

func (n *Notifier) unsubscribe(a ids.AccountNumberHash, ch chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if m := n.subs[a]; m != nil {
		delete(m, ch)
		// Drop the account key when its last subscriber leaves, so the map does
		// not accumulate one empty entry per account ever seen.
		if len(m) == 0 {
			delete(n.subs, a)
		}
	}
}

// Notify signals every subscriber of the account (non-blocking, coalescing — a full
// buffer means a poke is already pending). The server calls this after a push.
func (n *Notifier) Notify(a ids.AccountNumberHash) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for ch := range n.subs[a] {
		select {
		case ch <- struct{}{}:
		default: // already pending — coalesce
		}
	}
}

// SubscriberCount is for tests/observability (no IP/user data).
func (n *Notifier) SubscriberCount(a ids.AccountNumberHash) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.subs[a])
}

// Handler serves the SSE poke channel.
type Handler struct {
	notifier  *Notifier
	auth      *auth.TokenStore
	rl        RateLimiter // nil = policy disabled
	heartbeat time.Duration
}

// NewHandler wires the notifier + token store.
func NewHandler(n *Notifier, ts *auth.TokenStore) *Handler {
	return &Handler{notifier: n, auth: ts, heartbeat: DefaultHeartbeatInterval}
}

// WithPolicy attaches the shared per-account rate limiter (one token per
// connection attempt; nil = disabled).
func (h *Handler) WithPolicy(rl RateLimiter) *Handler {
	h.rl = rl
	return h
}

// WithHeartbeatInterval overrides the keep-alive cadence (tests).
func (h *Handler) WithHeartbeatInterval(d time.Duration) *Handler {
	h.heartbeat = d
	return h
}

// Register wires GET /sync/poke (the SSE channel).
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/sync/poke", h.handlePoke)
}

// rateReject mirrors the syncapi error envelope for the 429 class.
func rateReject(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error_code":"rate"}`))
}

// handlePoke streams contentless SSE events. Each event is literally empty (a bare
// "data:\n\n") — no id/version/count/cursor. Between events, a ":hb" comment line
// every heartbeat interval carries liveness and nothing else. Session-bound.
func (h *Handler) handlePoke(w http.ResponseWriter, r *http.Request) {
	const pfx = "Bearer "
	authz := r.Header.Get("Authorization")
	if len(authz) <= len(pfx) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tok, err := hex.DecodeString(authz[len(pfx):])
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	sess, aerr := h.auth.AuthenticateSession(ids.DeviceToken(tok))
	if aerr != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// One token per connection attempt from the SAME per-account bucket the
	// sync routes share — a reconnect-spinning client spends its own budget.
	if h.rl != nil && !h.rl.Allow(sess.Account) {
		rateReject(w)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	ch, ok := h.notifier.subscribe(sess.Account)
	if !ok {
		// At the per-account stream cap — same 429 class as the token bucket.
		rateReject(w)
		return
	}
	defer h.notifier.unsubscribe(sess.Account, ch)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	hb := time.NewTicker(h.heartbeat)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ch:
			// Zero-payload poke: empty data, nothing about which/what/how-much.
			if _, err := w.Write([]byte("data:\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case <-hb.C:
			// Keep-alive comment line — liveness only, no information. The write
			// error path is the server-side dead-connection detector.
			if _, err := w.Write([]byte(":hb\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
