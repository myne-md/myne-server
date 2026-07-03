// SPDX-License-Identifier: AGPL-3.0

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
	"time"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/auth/scram"
	"github.com/myne-md/myne-server/internal/ids"
)

// PreAuthLimiter gates the pre-auth (session-less) /auth/* surface with a single
// account-independent token bucket (nil = disabled). It is deliberately NOT the
// per-account RateLimiter: pre-auth requests have no session to key on, and keying
// on IP or the attacker-supplied account hash is forbidden (C4/AS14). See
// gcquota.GlobalLimiter.
type PreAuthLimiter interface {
	Allow() bool
}

// MaxAuthBodySize bounds every pre-auth /auth/* request body. SCRAM messages and
// the register verifier are tiny (nonces + hex-encoded 32-byte keys, well under
// 1 KiB); 8 KiB is generous but rejects an unauthenticated attacker streaming a
// giant JSON string field to exhaust memory (the syncapi/attachments handlers
// already gate their bodies with http.MaxBytesReader — these did not).
const MaxAuthBodySize = 8 * 1024

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
	// expiresAt bounds an init-without-final handshake so the h.hs map cannot grow
	// unboundedly (a memory-exhaustion DoS). Zero value = non-expiring (TTL disabled).
	expiresAt time.Time
}

// Handler serves the /auth/* routes.
type Handler struct {
	reg    *auth.Registry
	tokens *auth.TokenStore
	enroll *auth.Enrollment

	mu    sync.Mutex
	creds map[ids.AccountNumberHash]storedCredential
	hs    map[string]handshake

	// Pre-auth abuse bounds (0/nil = disabled — the mem/test default). preAuth is
	// the global pre-auth rate bucket; maxCreds caps the registered-account map;
	// maxHandshakes + hsTTL cap and expire the in-flight handshake map. now is the
	// injectable clock (default time.Now) so the TTL is deterministically testable.
	preAuth       PreAuthLimiter
	maxCreds      int
	maxHandshakes int
	hsTTL         time.Duration
	now           func() time.Time

	// serverCbind is the channel-binding data the server expects in client-final
	// (the TLS exporter in production; empty over loopback http — R3 wiring).
	serverCbind []byte

	// onAuthChange, when set (fs-backend persistence wired), is invoked AFTER a
	// handler that mutated auth state has released h.mu — never from inside a locked
	// region (it re-reads creds under h.mu, so a held lock would self-deadlock). nil
	// for the mem backend (no persistence).
	onAuthChange func()
}

// SetOnChange installs the persistence save hook (the authpersist coordinator's Save).
func (h *Handler) SetOnChange(fn func()) { h.onAuthChange = fn }

// maybeSave fires the persistence hook iff a mutation occurred. It is the body of a
// `defer h.maybeSave(&doSave)` that MUST be registered BEFORE `defer h.mu.Unlock()` so
// LIFO order runs the unlock first — guaranteeing h.mu is free when Save re-reads it.
func (h *Handler) maybeSave(do *bool) {
	if *do && h.onAuthChange != nil {
		h.onAuthChange()
	}
}

// New wires the auth primitives onto the HTTP surface.
func New(reg *auth.Registry, tokens *auth.TokenStore) *Handler {
	return &Handler{
		reg:    reg,
		tokens: tokens,
		enroll: auth.NewEnrollment(reg, tokens),
		creds:  make(map[ids.AccountNumberHash]storedCredential),
		hs:     make(map[string]handshake),
		now:    time.Now,
	}
}

// WithPreAuthLimiter attaches the global pre-auth rate bucket (nil = disabled).
func (h *Handler) WithPreAuthLimiter(g PreAuthLimiter) *Handler {
	h.preAuth = g
	return h
}

// WithLimits sets the pre-auth resource ceilings: maxCreds bounds the registered-
// account map, maxHandshakes bounds the in-flight SCRAM handshake map, and ttl is
// how long an init-without-final handshake survives before it is swept. A value of
// 0 for maxCreds/maxHandshakes disables that cap; ttl <= 0 disables handshake expiry.
func (h *Handler) WithLimits(maxCreds, maxHandshakes int, ttl time.Duration) *Handler {
	h.maxCreds = maxCreds
	h.maxHandshakes = maxHandshakes
	h.hsTTL = ttl
	return h
}

// WithClock overrides the handshake-TTL clock (tests inject a fake advancing clock;
// production uses the default time.Now set in New).
func (h *Handler) WithClock(now func() time.Time) *Handler {
	if now != nil {
		h.now = now
	}
	return h
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
	if h.preAuth != nil && !h.preAuth.Allow() {
		writeErr(w, http.StatusTooManyRequests, "rate")
		return
	}
	var req registerReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxAuthBodySize)).Decode(&req); err != nil {
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

	var doSave bool
	defer h.maybeSave(&doSave) // registered BEFORE the unlock defer → runs after it
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.creds[account]; exists {
		// First-write only — replacing a verifier requires an authed flow (not v0.1).
		writeErr(w, http.StatusConflict, "already_registered")
		return
	}
	// Cap the registered-account map so an unauthenticated register flood cannot grow
	// creds (and the persisted auth.json) without bound (503 = server at capacity,
	// distinct from a 429 rate signal). LoadCreds (boot) bypasses this — it restores
	// already-accepted state, not a new insert.
	if h.maxCreds > 0 && len(h.creds) >= h.maxCreds {
		writeErr(w, http.StatusServiceUnavailable, "capacity")
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
	doSave = true
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
	if h.preAuth != nil && !h.preAuth.Allow() {
		writeErr(w, http.StatusTooManyRequests, "rate")
		return
	}
	var req scramInitReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxAuthBodySize)).Decode(&req); err != nil {
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
	// Sweep expired handshakes then cap the in-flight map before inserting, so an
	// init-without-final flood cannot grow h.hs without bound (503 = at capacity).
	if h.hsTTL > 0 {
		for id, s := range h.hs {
			if !s.expiresAt.IsZero() && h.now().After(s.expiresAt) {
				delete(h.hs, id)
			}
		}
	}
	if h.maxHandshakes > 0 && len(h.hs) >= h.maxHandshakes {
		writeErr(w, http.StatusServiceUnavailable, "capacity")
		return
	}
	var expiresAt time.Time
	if h.hsTTL > 0 {
		expiresAt = h.now().Add(h.hsTTL)
	}
	h.hs[hid] = handshake{
		account:       account,
		username:      req.Username,
		clientNonce:   req.ClientNonce,
		combinedNonce: combined,
		expiresAt:     expiresAt,
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
	if h.preAuth != nil && !h.preAuth.Allow() {
		writeErr(w, http.StatusTooManyRequests, "rate")
		return
	}
	var req scramFinalReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxAuthBodySize)).Decode(&req); err != nil {
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

	var doSave bool
	defer h.maybeSave(&doSave) // registered BEFORE the unlock defer → runs after it
	h.mu.Lock()
	defer h.mu.Unlock()
	hs, exists := h.hs[req.HandshakeID]
	if !exists || (h.hsTTL > 0 && !hs.expiresAt.IsZero() && h.now().After(hs.expiresAt)) {
		// Unknown or expired handshake (init-without-final past its TTL). Burn it and
		// return the same 401 as any other failure (no extra enumeration signal).
		delete(h.hs, req.HandshakeID)
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
			doSave = true // a token was minted
		} else {
			writeJSON(w, scramFinalResp{Approved: false, ServerSignatureB64: base64.StdEncoding.EncodeToString(serverSig)})
			return
		}
	} else {
		res, eerr := h.enroll.Enroll(hs.account, device, path)
		doSave = true // Enroll registered the device (even when it lands pending)
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxAuthBodySize)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	device, ok := parseDevice(req.DeviceIDHex)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	var doSave bool
	defer h.maybeSave(&doSave)
	if err := h.reg.Approve(sess.Account, device); err != nil {
		writeErr(w, http.StatusNotFound, "device_not_found")
		return
	}
	doSave = true
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxAuthBodySize)).Decode(&req); err != nil {
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
	var doSave bool
	defer h.maybeSave(&doSave)
	h.tokens.RevokeDevice(sess.Account, device)
	_ = h.reg.Retire(sess.Account, device)
	doSave = true
	writeJSON(w, map[string]bool{"ok": true})
}

// --- Persistence snapshot/restore for the per-account SCRAM verifiers (creds) ---
//
// The handshake map (h.hs) is transient (in-flight SCRAM sessions) and is NOT
// persisted. The creds map IS — it is the per-account SCRAM verifier (a password-hash
// equivalent: StoredKey/ServerKey/Salt, never the password) the server needs to
// authenticate any future enrollment.

// PersistedCred is the serializable form of one account's SCRAM verifier. The byte
// fields are SCRAM verifier material (StoredKey/ServerKey/Salt) — treat as secret;
// never log them.
type PersistedCred struct {
	Account    ids.AccountNumberHash
	Username   string
	Salt       []byte
	Iterations int
	StoredKey  []byte
	ServerKey  []byte
}

// CredSnapshot returns a copy of every account's stored SCRAM verifier.
func (h *Handler) CredSnapshot() []PersistedCred {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]PersistedCred, 0, len(h.creds))
	for acct, sc := range h.creds {
		out = append(out, PersistedCred{
			Account:    acct,
			Username:   sc.username,
			Salt:       sc.cred.Salt,
			Iterations: sc.cred.Iterations,
			StoredKey:  sc.cred.StoredKey,
			ServerKey:  sc.cred.ServerKey,
		})
	}
	return out
}

// LoadCreds REPLACES the creds map from a snapshot by direct assignment (never through
// handleRegister, so the first-write-only guard is not re-triggered). Idempotent.
// Boot-only. h.hs is left empty (handshakes never persist).
func (h *Handler) LoadCreds(snap []PersistedCred) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.creds = make(map[ids.AccountNumberHash]storedCredential, len(snap))
	for _, c := range snap {
		h.creds[c.Account] = storedCredential{
			username: c.Username,
			cred: scram.Credential{
				Salt:       c.Salt,
				Iterations: c.Iterations,
				StoredKey:  c.StoredKey,
				ServerKey:  c.ServerKey,
			},
		}
	}
}
