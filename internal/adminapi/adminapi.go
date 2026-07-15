// SPDX-License-Identifier: AGPL-3.0

// Package adminapi is the operator console's admin API (MYND-506). It is served over
// a LOCAL Unix domain socket — never a TCP port or the public edge — with access
// governed by filesystem permissions on the socket (no bearer secret): whoever can
// reach the socket file (root / `docker exec` on the box) can drive it. It is a live
// projection of already-persisted enforcement state only (account hash, stored bytes,
// device count, plan fields) and NEVER a new observation channel: no request history,
// no last-seen wall-clocks, no per-account time series (the MYND-440 aggregate-only
// invariant). The `myne-server admin` CLI is a thin client over this same API, and a
// future stdlib web panel reuses it.
package adminapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"

	"github.com/myne-md/myne-server/internal/accounts"
	"github.com/myne-md/myne-server/internal/ids"
)

// Handler owns the admin API routes. It depends on the rest of the server only via
// closures + the accounts store, so it stays decoupled from store/auth/attachments.
type Handler struct {
	mux         *http.ServeMux
	listAccts   func() []ids.AccountNumberHash
	usedBytes   func(ids.AccountNumberHash) uint64 // stored ciphertext bytes (blobs + attachments; the AS17 total)
	deviceCount func(ids.AccountNumberHash) uint64
	policy      *accounts.Store
	maxAccounts uint64                            // 0 = unlimited
	del         func(ids.AccountNumberHash) error // irreversible account delete (nil = disabled)
}

// WithDelete installs the irreversible account-delete path (MYND-506): the caller's
// closure removes the account's vault + attachments + auth + policy. nil = the DELETE
// route reports 503.
func (h *Handler) WithDelete(fn func(ids.AccountNumberHash) error) *Handler {
	h.del = fn
	return h
}

// New builds the admin handler. All dependencies are injected as closures / the
// accounts store so this package pulls in no server internals. nil deps make the
// read routes report zeros (used by the transport-only skeleton test).
func New(listAccts func() []ids.AccountNumberHash, usedBytes, deviceCount func(ids.AccountNumberHash) uint64, policy *accounts.Store, maxAccounts uint64) *Handler {
	h := &Handler{
		mux:         http.NewServeMux(),
		listAccts:   listAccts,
		usedBytes:   usedBytes,
		deviceCount: deviceCount,
		policy:      policy,
		maxAccounts: maxAccounts,
	}
	h.mux.HandleFunc("GET /admin/ping", h.handlePing)
	h.mux.HandleFunc("GET /admin/accounts", h.handleListAccounts)
	h.mux.HandleFunc("GET /admin/accounts/{hash}", h.handleShowAccount)
	h.mux.HandleFunc("GET /admin/stats", h.handleStats)
	h.mux.HandleFunc("POST /admin/accounts/{hash}/freeze", h.handleFreeze)
	h.mux.HandleFunc("POST /admin/accounts/{hash}/unfreeze", h.handleUnfreeze)
	h.mux.HandleFunc("POST /admin/accounts/{hash}/quota", h.handleSetQuota)
	h.mux.HandleFunc("POST /admin/accounts/{hash}/max-devices", h.handleSetMaxDevices)
	h.mux.HandleFunc("DELETE /admin/accounts/{hash}", h.handleDelete)
	return h
}

func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
	a, ok := ids.ParseAccountNumberHash(r.PathValue("hash"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_account_hash"})
		return
	}
	if h.del == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "delete_unavailable"})
		return
	}
	if err := h.del(a); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": hex.EncodeToString(a[:])})
}

// Mux returns the admin HTTP handler (served over the Unix socket).
func (h *Handler) Mux() http.Handler { return h.mux }

// accountView is the merged live-stats + operator-policy projection of one account.
// It carries NO timestamp / activity / request-history field (MYND-440 aggregate-only).
type accountView struct {
	AccountHash        string `json:"account_hash"`
	StoredBytes        uint64 `json:"stored_bytes"`
	DeviceCount        uint64 `json:"device_count"`
	Frozen             bool   `json:"frozen"`
	QuotaOverrideBytes uint64 `json:"quota_override_bytes,omitempty"`
	MaxDevicesOverride uint64 `json:"max_devices_override,omitempty"`
}

type statsView struct {
	TotalAccounts    uint64 `json:"total_accounts"`
	TotalStoredBytes uint64 `json:"total_stored_bytes"`
	MaxAccounts      uint64 `json:"max_accounts"` // 0 = unlimited
}

func (h *Handler) handlePing(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) view(a ids.AccountNumberHash) accountView {
	v := accountView{AccountHash: hex.EncodeToString(a[:])}
	if h.usedBytes != nil {
		v.StoredBytes = h.usedBytes(a)
	}
	if h.deviceCount != nil {
		v.DeviceCount = h.deviceCount(a)
	}
	if h.policy != nil {
		p := h.policy.Get(a)
		v.Frozen = p.Frozen
		v.QuotaOverrideBytes = p.QuotaOverrideBytes
		v.MaxDevicesOverride = p.MaxDevicesOverride
	}
	return v
}

func (h *Handler) handleListAccounts(w http.ResponseWriter, _ *http.Request) {
	var accts []ids.AccountNumberHash
	if h.listAccts != nil {
		accts = h.listAccts()
	}
	out := make([]accountView, 0, len(accts))
	for _, a := range accts {
		out = append(out, h.view(a))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) handleShowAccount(w http.ResponseWriter, r *http.Request) {
	a, ok := ids.ParseAccountNumberHash(r.PathValue("hash"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_account_hash"})
		return
	}
	writeJSON(w, http.StatusOK, h.view(a))
}

func (h *Handler) handleStats(w http.ResponseWriter, _ *http.Request) {
	var accts []ids.AccountNumberHash
	if h.listAccts != nil {
		accts = h.listAccts()
	}
	s := statsView{TotalAccounts: uint64(len(accts)), MaxAccounts: h.maxAccounts}
	if h.usedBytes != nil {
		for _, a := range accts {
			s.TotalStoredBytes += h.usedBytes(a)
		}
	}
	writeJSON(w, http.StatusOK, s)
}

// setReq is the body for the value-carrying enforcement writes (quota / max-devices).
// 0 clears the override (falls back to the global default).
type setReq struct {
	Value uint64 `json:"value"`
}

func (h *Handler) handleFreeze(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(p *accounts.Policy) { p.Frozen = true })
}

func (h *Handler) handleUnfreeze(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(p *accounts.Policy) { p.Frozen = false })
}

func (h *Handler) handleSetQuota(w http.ResponseWriter, r *http.Request) {
	var req setReq
	if !decode(w, r, &req) {
		return
	}
	h.mutate(w, r, func(p *accounts.Policy) { p.QuotaOverrideBytes = req.Value })
}

func (h *Handler) handleSetMaxDevices(w http.ResponseWriter, r *http.Request) {
	var req setReq
	if !decode(w, r, &req) {
		return
	}
	h.mutate(w, r, func(p *accounts.Policy) { p.MaxDevicesOverride = req.Value })
}

// mutate parses the account hash, applies the policy change (which persists via the
// flusher, and drops the entry when it returns to default so the store stays sparse),
// and returns the updated view. A malformed hash is a clean 400; a well-formed hash
// that has no data yet is not an error — the operator works from `admin list`, and a
// default-valued write leaves no entry.
func (h *Handler) mutate(w http.ResponseWriter, r *http.Request, apply func(*accounts.Policy)) {
	a, ok := ids.ParseAccountNumberHash(r.PathValue("hash"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_account_hash"})
		return
	}
	if h.policy == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy_store_unavailable"})
		return
	}
	h.policy.Update(a, apply)
	writeJSON(w, http.StatusOK, h.view(a))
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Listen binds the admin Unix domain socket at path with 0600 perms (a stale socket
// from a prior run is removed first). It returns a nil listener when path == "" — the
// admin API is disabled by default. A bind failure is returned so the caller can fail
// startup rather than serve without the admin surface.
func Listen(path string) (net.Listener, error) {
	if path == "" {
		return nil, nil
	}
	_ = os.Remove(path) // clear a stale socket left by a crashed prior run
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve serves handler on ln until ctx is cancelled, then gracefully shuts down. Run
// it in a goroutine. It is a no-op when ln is nil (admin API disabled).
func Serve(ctx context.Context, ln net.Listener, handler http.Handler) {
	if ln == nil {
		return
	}
	srv := &http.Server{Handler: handler}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	_ = srv.Serve(ln) // returns http.ErrServerClosed on graceful shutdown
}
