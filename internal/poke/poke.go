// SPDX-License-Identifier: AGPL-3.0-or-later

// Package poke is the change-notification layer (MYND-423). Polling (the pull
// endpoint) is the privacy-default baseline — the server sees a device only at poll
// time. SSE is the OPT-IN low-latency layer (an open SSE is a continuous presence
// signal, A13 — so it is never the default). The poke is LITERALLY zero-payload: it
// carries no note-id, no version, no count, no cursor — only "something changed,
// come pull". The channel is session-bound (a spoofed poke is at worst low-severity
// DoS, but still must be authenticated).
package poke

import (
	"encoding/hex"
	"net/http"
	"sync"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
)

// Notifier fans a contentless "changed" signal out to a vault's SSE subscribers.
type Notifier struct {
	mu   sync.Mutex
	subs map[ids.AccountNumberHash]map[chan struct{}]struct{}
}

// NewNotifier returns an empty notifier.
func NewNotifier() *Notifier {
	return &Notifier{subs: make(map[ids.AccountNumberHash]map[chan struct{}]struct{})}
}

func (n *Notifier) subscribe(a ids.AccountNumberHash) chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.subs[a] == nil {
		n.subs[a] = make(map[chan struct{}]struct{})
	}
	ch := make(chan struct{}, 1)
	n.subs[a][ch] = struct{}{}
	return ch
}

func (n *Notifier) unsubscribe(a ids.AccountNumberHash, ch chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if m := n.subs[a]; m != nil {
		delete(m, ch)
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

// Handler serves the opt-in SSE poke channel.
type Handler struct {
	notifier *Notifier
	auth     *auth.TokenStore
}

// NewHandler wires the notifier + token store.
func NewHandler(n *Notifier, ts *auth.TokenStore) *Handler {
	return &Handler{notifier: n, auth: ts}
}

// Register wires GET /sync/poke (the opt-in SSE channel).
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/sync/poke", h.handlePoke)
}

// handlePoke streams contentless SSE events. Each event is literally empty (a bare
// "data:\n\n") — no id/version/count/cursor. Session-bound.
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
	flusher, ok := w.(http.Flusher)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	ch := h.notifier.subscribe(sess.Account)
	defer h.notifier.unsubscribe(sess.Account, ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ch:
			// Zero-payload poke: empty data, nothing about which/what/how-much.
			_, _ = w.Write([]byte("data:\n\n"))
			flusher.Flush()
		}
	}
}
