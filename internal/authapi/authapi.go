// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authapi is the HTTP surface for device authentication + management
// (MYND-420 HTTP exposure / MYND-425 client enrollment): SCRAM-SHA-256-PLUS
// handshake, the device-approval gate + per-device token issuance, and device
// list/approve/revoke. It wires the existing auth primitives (registry, tokens,
// enrollment, scram) onto HTTP — it owns no crypto.
//
// Flow (the client side is MYND-425):
//  1. POST /auth/register   — upload the SCRAM verifier for an account (the
//     server stores StoredKey/ServerKey, never the secret). First-write only.
//  2. POST /auth/scram/init — client-first (username + client_nonce) → the
//     server returns a combined nonce + salt + iterations + a handshake id.
//  3. POST /auth/scram/final — the client proves the secret (client-final) +
//     names its device + path; the server verifies, applies the approval gate,
//     and issues a per-device token (or reports pending).
//  4. GET  /auth/devices            — authed: the device roster.
//     POST /auth/devices/approve    — authed: an existing device approves a
//                                     pending one (the password-path gate).
//     POST /auth/devices/revoke     — authed: revoke a device's token (removal).
//
// R3 (channel binding): the `-PLUS` binding requires the TLS exporter. Over the
// loopback-http harness there is no exporter, so the server's cbind is empty
// (the client matches); over real TLS both sides feed the exporter. Wiring the
// live exporter into `serverCbind` is the R3-pending step (mirrors the client
// rustls transport). Blind relay: the server never sees plaintext.

package authapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/auth/scram"
	"github.com/myne-md/myne-server/internal/ids"
)

// storedCredential is the per-account SCRAM verifier + its username.
type storedCredential struct {
	username string
	cred     scram.Credential
}

// handshake is the ephemeral server-side SCRAM session between init and final.
type handshake struct {
	account       ids.AccountNumberHash
	username      string
	clientNonce   string
	combinedNonce string
}

// Handler serves the /auth/* routes.
type Handler struct {
	reg    *auth.Registry
	tokens *auth.TokenStore
	enroll *auth.Enrollment

	mu    sync.Mutex
	creds map[ids.AccountNumberHash]storedCredential
	hs    map[string]handshake

	// serverCbind is the channel-binding data the server expects in client-final
	// (the TLS exporter in production; empty over loopback http — R3 wiring).
	serverCbind []byte
}

// New wires the auth primitives onto the HTTP surface.
func New(reg *auth.Registry, tokens *auth.TokenStore) *Handler {
	return &Handler{
		reg:    reg,
		tokens: tokens,
		enroll: auth.NewEnrollment(reg, tokens),
		creds:  make(map[ids.AccountNumberHash]storedCredential),
		hs:     make(map[string]handshake),
	}
}

// Register wires the auth routes onto a mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/auth/register", h.handleRegister)
	mux.HandleFunc("/auth/scram/init", h.handleScramInit)
	mux.HandleFunc("/auth/scram/final", h.handleScramFinal)
	mux.HandleFunc("/auth/devices", h.handleDevices)
	mux.HandleFunc("/auth/devices/approve", h.handleApprove)
	mux.HandleFunc("/auth/devices/revoke", h.handleRevoke)
}

func writeErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error_code": code})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func parseAccount(s string) (ids.AccountNumberHash, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ids.AccountNumberHashLen {
		return ids.AccountNumberHash{}, false
	}
	var a ids.AccountNumberHash
	copy(a[:], b)
	return a, true
}

func parseDevice(s string) (ids.DeviceID, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ids.DeviceIDLen {
		return ids.DeviceID{}, false
	}
	var d ids.DeviceID
	copy(d[:], b)
	return d, true
}

// --- POST /auth/register: upload the SCRAM verifier (first-write only) ---

type registerReq struct {
	AccountHashHex string `json:"account_hash_hex"`
	Username       string `json:"username"`
	SaltHex        string `json:"salt_hex"`
	Iterations     int    `json:"iterations"`
	StoredKeyHex   string `json:"stored_key_hex"`
	ServerKeyHex   string `json:"server_key_hex"`
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	account, ok := parseAccount(req.AccountHashHex)
	salt, e1 := hex.DecodeString(req.SaltHex)
	storedKey, e2 := hex.DecodeString(req.StoredKeyHex)
	serverKey, e3 := hex.DecodeString(req.ServerKeyHex)
	if !ok || e1 != nil || e2 != nil || e3 != nil || req.Iterations < 1 || req.Username == "" {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.creds[account]; exists {
		// First-write only — replacing a verifier requires an authed flow (not v0.1).
		writeErr(w, http.StatusConflict, "already_registered")
		return
	}
	h.creds[account] = storedCredential{
		username: req.Username,
		cred: scram.Credential{
			Salt:       salt,
			Iterations: req.Iterations,
			StoredKey:  storedKey,
			ServerKey:  serverKey,
		},
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// --- POST /auth/scram/init: client-first → server-first + handshake id ---

type scramInitReq struct {
	AccountHashHex string `json:"account_hash_hex"`
	Username       string `json:"username"`
	ClientNonce    string `json:"client_nonce"`
}

type scramInitResp struct {
	HandshakeID   string `json:"handshake_id"`
	CombinedNonce string `json:"combined_nonce"`
	SaltHex       string `json:"salt_hex"`
	Iterations    int    `json:"iterations"`
}

func (h *Handler) handleScramInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	var req scramInitReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	account, ok := parseAccount(req.AccountHashHex)
	if !ok || req.ClientNonce == "" {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	sc, exists := h.creds[account]
	if !exists || sc.username != req.Username {
		// Do not distinguish unknown-account from wrong-username (no enumeration).
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	serverNonce, err := randHex(16)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	combined := req.ClientNonce + serverNonce
	hid, err := randHex(16)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	h.hs[hid] = handshake{
		account:       account,
		username:      req.Username,
		clientNonce:   req.ClientNonce,
		combinedNonce: combined,
	}
	writeJSON(w, scramInitResp{
		HandshakeID:   hid,
		CombinedNonce: combined,
		SaltHex:       hex.EncodeToString(sc.cred.Salt),
		Iterations:    sc.cred.Iterations,
	})
}

// --- POST /auth/scram/final: verify proof + enroll/approve → token ---

type scramFinalReq struct {
	HandshakeID string `json:"handshake_id"`
	ClientFinal string `json:"client_final"` // the SCRAM client-final-message
	DeviceIDHex string `json:"device_id_hex"`
	Path        string `json:"path"` // "password" | "recovery"
}

type scramFinalResp struct {
	Approved           bool   `json:"approved"`
	TokenHex           string `json:"token_hex,omitempty"`
	ServerSignatureB64 string `json:"server_signature_b64,omitempty"`
}

func (h *Handler) handleScramFinal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	var req scramFinalReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	device, ok := parseDevice(req.DeviceIDHex)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	var path auth.EnrollPath
	switch req.Path {
	case "password":
		path = auth.PathPassword
	case "recovery":
		path = auth.PathRecovery
	default:
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	hs, exists := h.hs[req.HandshakeID]
	if !exists {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	sc := h.creds[hs.account]

	serverSig, err := scram.VerifyClientFinal(
		sc.cred, hs.username, hs.clientNonce, hs.combinedNonce, h.serverCbind, req.ClientFinal,
	)
	if err != nil {
		// One-shot handshake: a failed proof burns it (no online guessing reuse).
		delete(h.hs, req.HandshakeID)
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	delete(h.hs, req.HandshakeID)

	// SCRAM proved account ownership. Apply the gate. If the device is already
	// registered + approved (a pending device returning after approval), issue
	// its token via CompleteApproval; otherwise Enroll (which gates new devices).
	var token ids.DeviceToken
	if rec, found := h.reg.Get(hs.account, device); found {
		if rec.Approved && !rec.Retired {
			t, cerr := h.enroll.CompleteApproval(hs.account, device)
			if cerr != nil {
				writeErr(w, http.StatusForbidden, "pending_approval")
				return
			}
			token = t
		} else {
			writeJSON(w, scramFinalResp{Approved: false, ServerSignatureB64: base64.StdEncoding.EncodeToString(serverSig)})
			return
		}
	} else {
		res, eerr := h.enroll.Enroll(hs.account, device, path)
		if errors.Is(eerr, auth.ErrPendingApproval) {
			writeJSON(w, scramFinalResp{Approved: false, ServerSignatureB64: base64.StdEncoding.EncodeToString(serverSig)})
			return
		}
		if eerr != nil {
			writeErr(w, http.StatusInternalServerError, "internal")
			return
		}
		token = res.Token
	}

	writeJSON(w, scramFinalResp{
		Approved:           true,
		TokenHex:           hex.EncodeToString(token),
		ServerSignatureB64: base64.StdEncoding.EncodeToString(serverSig),
	})
}

// --- authed device management ---

func (h *Handler) session(r *http.Request) (auth.Session, bool) {
	const pfx = "Bearer "
	authz := r.Header.Get("Authorization")
	if len(authz) <= len(pfx) || authz[:len(pfx)] != pfx {
		return auth.Session{}, false
	}
	tok, err := hex.DecodeString(authz[len(pfx):])
	if err != nil {
		return auth.Session{}, false
	}
	sess, err := h.tokens.AuthenticateSession(ids.DeviceToken(tok))
	if err != nil {
		return auth.Session{}, false
	}
	return sess, true
}

type deviceWire struct {
	DeviceIDHex string `json:"device_id_hex"`
	Approved    bool   `json:"approved"`
	Retired     bool   `json:"retired"`
}

func (h *Handler) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	sess, ok := h.session(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	recs := h.reg.List(sess.Account)
	out := make([]deviceWire, 0, len(recs))
	for _, rec := range recs {
		out = append(out, deviceWire{
			DeviceIDHex: hex.EncodeToString(rec.DeviceID[:]),
			Approved:    rec.Approved,
			Retired:     rec.Retired,
		})
	}
	writeJSON(w, map[string][]deviceWire{"devices": out})
}

type deviceActionReq struct {
	DeviceIDHex string `json:"device_id_hex"`
}

func (h *Handler) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	sess, ok := h.session(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var req deviceActionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	device, ok := parseDevice(req.DeviceIDHex)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := h.reg.Approve(sess.Account, device); err != nil {
		writeErr(w, http.StatusNotFound, "device_not_found")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	sess, ok := h.session(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var req deviceActionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	device, ok := parseDevice(req.DeviceIDHex)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	// Revoke the token (availability — sync stops to that device) + retire the
	// registry record. device_id is NOT destroyed (SYNC-2: revoking the token
	// never touches device_id).
	h.tokens.RevokeDevice(sess.Account, device)
	_ = h.reg.Retire(sess.Account, device)
	writeJSON(w, map[string]bool{"ok": true})
}
