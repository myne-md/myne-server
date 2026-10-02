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
// R3 (channel binding): the `-PLUS` binding is WIRED (F5). When a request arrives
// over app-terminated TLS 1.3 the server binds to the live RFC 9266 tls-exporter
// (`requestCbind`), advertises it in the init response (`Cbind`), and rejects a
// client-final that omits it; behind a TLS-terminating proxy or on loopback http
// there is no exporter, so the server binds to the empty `serverCbind` and the
// client matches (the pre-F5 behavior, unchanged). The Go↔rustls exporter is proven
// byte-identical under TLS 1.3 (features/.../review-r3; scratchpad probe). REMAINING
// GATES (not code): the app-terminated-TLS deploy + Caddy TCP-passthrough (the operations repository)
// and the standing MYND-420 R3 primitive-level review. Blind relay: never sees plaintext.

package authapi

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/auth/scram"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
	"github.com/myne-md/myne-server/internal/profiles"
	"github.com/myne-md/myne-server/internal/relay"
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

// MinInviteCodeLen is the shortest invite code a server will accept. A code
// shorter than this is refused at startup (httpapi.loadConfig), because the
// pre-auth limiter is a single global bucket that cannot key on source: the
// code's own entropy is the primary defence against guessing.
const MinInviteCodeLen = 32

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

	// members is the person↔vault access table and memberTks the per-vault
	// bearer tokens it issues (myne-md/myne#711, decisions/protocol/0599). They
	// are created in New so the B2B routes are always registered — self-host and
	// hosted run the identical route set — and are exposed so the sync surface's
	// owner-only vault.meta refusal (task 9) can consume the same authority
	// rather than re-deriving it.
	members   *membership.Table
	memberTks *membership.TokenStore
	relay     *relay.Store
	profs     *profiles.Store
	// profileDeleteGrace is how long a removed member's profiles survive before
	// reclamation (0 or negative = DefaultProfileDeleteGrace).
	profileDeleteGrace time.Duration

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

	// inviteCode, when non-empty, gates NEW-account registration behind a shared
	// invite code (MYNE_INVITE_CODE). "" = open registration. It is compared in
	// constant time and is never logged, stored, or associated with an account;
	// an account that already exists is unaffected (a later device enrols through
	// the normal approval flow), which is why the check sits after the
	// already-registered branch in handleRegister.
	inviteCode string

	// requireChannelBinding, when non-nil, is asked whether an account refuses
	// unbound sessions (MYND-577's per-account opt-out). nil = no account
	// refuses, which is the shipped behaviour; the hook exists so the opt-out
	// lands without a schema or wire change.
	requireChannelBinding func(ids.AccountNumberHash) bool

	// serverCbind is the channel-binding data the server expects in client-final
	// (the TLS exporter in production; empty over loopback http — R3 wiring).
	serverCbind []byte

	// onAuthChange, when set (fs-backend persistence wired), is invoked AFTER a
	// handler that mutated auth state has released h.mu — never from inside a locked
	// region (it re-reads creds under h.mu, so a held lock would self-deadlock). nil
	// for the mem backend (no persistence).
	onAuthChange func()

	// frozen / maxDevices are the operator enforcement gates (MYND-506), injected as
	// closures over the accounts store so this package stays decoupled. frozen blocks
	// enrollment token-minting for a frozen account; maxDevices returns the account's
	// effective device cap (0 = unlimited), enforced against the active-device count
	// when a NEW device enrolls. nil = enforcement disabled (mem/test default).
	frozen     func(account ids.AccountNumberHash) bool
	maxDevices func(account ids.AccountNumberHash) uint64
}

// WithAccountGate installs the operator enforcement gates (MYND-506): frozen blocks
// enrollment for a frozen account; maxDevices returns the effective per-account device
// cap (0 = unlimited), enforced when a new device enrolls. Either may be nil.
func (h *Handler) WithAccountGate(frozen func(ids.AccountNumberHash) bool, maxDevices func(ids.AccountNumberHash) uint64) *Handler {
	h.frozen = frozen
	h.maxDevices = maxDevices
	return h
}

// DeleteAccount removes an account's SCRAM verifier + device registry + device tokens
// (MYND-506, the operator/self-service deletion path) and persists the change. The
// caller removes the account's blob + attachment data separately (remove-then-forget).
func (h *Handler) DeleteAccount(account ids.AccountNumberHash) {
	h.mu.Lock()
	delete(h.creds, account)
	h.mu.Unlock()
	h.reg.DeleteAccount(account)
	h.tokens.DeleteAccountTokens(account)
	if h.onAuthChange != nil {
		h.onAuthChange()
	}
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
	table := membership.New()
	return &Handler{
		reg:       reg,
		tokens:    tokens,
		enroll:    auth.NewEnrollment(reg, tokens),
		members:   table,
		memberTks: membership.NewTokenStore(table),
		relay:     relay.NewStore(),
		profs:     profiles.NewStore(),
		creds:     make(map[ids.AccountNumberHash]storedCredential),
		hs:        make(map[string]handshake),
		now:       time.Now,
	}
}

// WithPreAuthLimiter attaches the global pre-auth rate bucket (nil = disabled).
// WithRequireChannelBinding installs the per-account "bound sessions only"
// predicate (MYND-577). Unwired today; the seam exists so the opt-out can land
// without a schema or wire change.
//
// An account that returns true refuses any session the server could not bind to
// real exporter material. That is NOT the same as refusing browser access, and
// the doc used to say it was: whether a binding exists is a property of the
// DEPLOYMENT, not of the client. Behind a terminating reverse proxy the server
// has no exporter, so this refuses every client including the native ones;
// where the server terminates TLS itself it admits every native client. A
// web-vs-native distinction needs a different signal.
func (h *Handler) WithRequireChannelBinding(p func(ids.AccountNumberHash) bool) *Handler {
	h.requireChannelBinding = p
	return h
}

func (h *Handler) WithPreAuthLimiter(g PreAuthLimiter) *Handler {
	h.preAuth = g
	return h
}

// WithInviteCode gates new-account registration behind a shared invite code
// ("" = open registration, the self-host default). The code is compared in
// constant time at POST /auth/register and is never logged, stored, or
// associated with an account.
func (h *Handler) WithInviteCode(code string) *Handler {
	h.inviteCode = code
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
	mux.HandleFunc("/auth/verifier", h.handleReplaceVerifier)
	mux.HandleFunc("/auth/scram/init", h.handleScramInit)
	mux.HandleFunc("/auth/scram/final", h.handleScramFinal)
	mux.HandleFunc("/auth/devices", h.handleDevices)
	mux.HandleFunc("/auth/devices/approve", h.handleApprove)
	mux.HandleFunc("/auth/devices/revoke", h.handleRevoke)
	// B2B person↔vault membership (myne-md/myne#711, decisions/protocol/0599).
	// Person accounts themselves use the /auth/* routes above with their
	// person_id_hash as the account id (see b2b.go's header).
	mux.HandleFunc("POST /b2b/vaults/{account_hash}/members", h.handleBindMember)
	mux.HandleFunc("DELETE /b2b/vaults/{account_hash}/members/{person_id}", h.handleRemoveMember)
	mux.HandleFunc("POST /b2b/invites", h.handleCreateInvite)
	mux.HandleFunc("GET /b2b/invites", h.handleListInvites)
	mux.HandleFunc("GET /b2b/vaults/{account_hash}/invites", h.handleListVaultInvites)
	mux.HandleFunc("POST /b2b/invites/{invite_id}/claim", h.handleClaimInvite)
	// Person-private AI profiles (myne-md/myne#711 task 16): a vault-scoped,
	// person-authorized namespace, separate from the shared group manifest.
	mux.HandleFunc("PUT /b2b/vaults/{account_hash}/profiles/{profile_id}", h.handlePutProfile)
	mux.HandleFunc("GET /b2b/vaults/{account_hash}/profiles/{profile_id}", h.handleGetProfile)
}

// Relay returns the sealed-invite store for a caller that needs it (the client
// acceptance flow and the operator surfaces read it through the routes; this is
// here for tests and for the removal path's cleanup).
func (h *Handler) Relay() *relay.Store { return h.relay }

func writeErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error_code": code})
}

// inviteCodeMatches compares the presented invite code against the configured
// one in constant time with respect to BOTH content and length: it hashes both
// (SHA-256, so both inputs are 32 bytes) before the constant-time compare, so a
// length mismatch cannot leak the configured code's length through timing.
func inviteCodeMatches(presented, configured string) bool {
	p := sha256.Sum256([]byte(presented))
	c := sha256.Sum256([]byte(configured))
	return subtle.ConstantTimeCompare(p[:], c[:]) == 1
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

func parseDevice(s string) (ids.DeviceID, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ids.DeviceIDLen {
		return ids.DeviceID{}, false
	}
	var d ids.DeviceID
	copy(d[:], b)
	return d, true
}

// canonicalUsername is the ONLY accepted SCRAM username for an account: the
// lowercase hex of its account hash (AS9). Single-sourced so the register door
// and the init door cannot drift on the encoding; see server-protocol.md §3.1.
func canonicalUsername(a ids.AccountNumberHash) string {
	return hex.EncodeToString(a[:])
}

// --- POST /auth/register: upload the SCRAM verifier (first-write only) ---

type registerReq struct {
	AccountHashHex string `json:"account_hash_hex"`
	Username       string `json:"username"`
	SaltHex        string `json:"salt_hex"`
	Iterations     int    `json:"iterations"`
	StoredKeyHex   string `json:"stored_key_hex"`
	ServerKeyHex   string `json:"server_key_hex"`
	// InviteCode is the shared admission code for a gated server. Absent from an
	// older client and ignored by an ungated server, so the field is forward and
	// backward compatible at the wire shape level.
	InviteCode string `json:"invite_code"`
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
	account, ok := ids.ParseAccountNumberHash(req.AccountHashHex)
	salt, e1 := hex.DecodeString(req.SaltHex)
	storedKey, e2 := hex.DecodeString(req.StoredKeyHex)
	serverKey, e3 := hex.DecodeString(req.ServerKeyHex)
	// AS9: the SCRAM username MUST be the canonical lowercase hex of the account
	// hash — never the raw account number (bearer semantics). Enforced at the
	// door so the persisted auth state structurally cannot contain a raw account
	// number, even from an outdated client (server-protocol.md §3.1).
	if !ok || e1 != nil || e2 != nil || e3 != nil || req.Iterations < 1 ||
		req.Username != canonicalUsername(account) {
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
	// Closed-beta admission gate. Only a NEW account is asked for the code: an
	// account that already exists returned above, so a later device enrols
	// without one. Constant-time compare; the presented code is never logged.
	if h.inviteCode != "" {
		switch {
		case req.InviteCode == "":
			writeErr(w, http.StatusForbidden, "invite_code_required")
			return
		case !inviteCodeMatches(req.InviteCode, h.inviteCode):
			writeErr(w, http.StatusForbidden, "invite_code_invalid")
			return
		}
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

// --- POST /auth/verifier: REPLACE the SCRAM verifier (authed) ---
//
// `/auth/register` is first-write-only by design: an unauthenticated caller must
// not be able to overwrite an account's credential. That leaves no path at all
// for the one case where the verifier legitimately changes — a client-side
// whole-vault re-key (`protocol.md` §10.4, myne-md/myne#429). The SCRAM secret is
// `derive_subkey(root_key, ServerAuth)`, so a new `root_key` means a new
// verifier; without this route the account keeps the old one, an already-enrolled
// device keeps working only until its bearer token expires, and then every
// handshake — including a new device's enrolment — fails 401 forever.
//
// The authorization is the bearer token itself: only a device that has ALREADY
// authenticated against the account may replace its verifier, and it may replace
// only its OWN account's (the account comes from the session, never from the
// body). So this is not a weaker `/auth/register`; it is a strictly stronger one,
// and the unauthenticated route keeps its first-write-only rule unchanged.
//
// The server learns nothing new: a verifier is opaque to it either way, and it
// already stores one.

type replaceVerifierReq struct {
	Username     string `json:"username"`
	SaltHex      string `json:"salt_hex"`
	Iterations   int    `json:"iterations"`
	StoredKeyHex string `json:"stored_key_hex"`
	ServerKeyHex string `json:"server_key_hex"`
}

func (h *Handler) handleReplaceVerifier(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	// The account is taken from the SESSION, never from the body: a device may
	// replace only the verifier of the account it authenticated against.
	authz := r.Header.Get("Authorization")
	const pfx = "Bearer "
	if !strings.HasPrefix(authz, pfx) {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	tok, err := hex.DecodeString(strings.TrimPrefix(authz, pfx))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	sess, err := h.tokens.AuthenticateSession(ids.DeviceToken(tok))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, auth.FailureCode(err))
		return
	}
	var req replaceVerifierReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxAuthBodySize)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	salt, e1 := hex.DecodeString(req.SaltHex)
	storedKey, e2 := hex.DecodeString(req.StoredKeyHex)
	serverKey, e3 := hex.DecodeString(req.ServerKeyHex)
	// Same AS9 door as /auth/register: the SCRAM username MUST be the canonical
	// lowercase hex of the account hash, so persisted auth state structurally
	// cannot come to contain a raw account number.
	if e1 != nil || e2 != nil || e3 != nil || req.Iterations < 1 ||
		req.Username != canonicalUsername(sess.Account) {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}

	var doSave bool
	defer h.maybeSave(&doSave)
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.creds[sess.Account]; !exists {
		// Nothing to replace. Not a capacity insert either — an authenticated
		// device implies a registered account, so this is a client bug rather
		// than a route to grow `creds` through.
		writeErr(w, http.StatusNotFound, "not_registered")
		return
	}
	h.creds[sess.Account] = storedCredential{
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
	// Cbind advertises the channel-binding the client-final must carry: "tls-exporter"
	// when this request arrived over app-terminated TLS 1.3 (F5 — the client then
	// computes the RFC 9266 exporter on its auth connection and sends it), or omitted
	// (empty) behind a TLS-terminating proxy / loopback http, where the server also
	// verifies against an empty cbind. This is the negotiation that keeps a mixed
	// fleet from pairing a real-cbind end with an empty-cbind end.
	Cbind string `json:"cbind,omitempty"`
}

// requestCbind is the channel-binding data the SCRAM handshake binds to for THIS
// request: the RFC 9266 tls-exporter when the request arrived over app-terminated
// TLS 1.3 (proven byte-identical to the rustls client's — F5), else h.serverCbind
// (empty) so a proxy-terminated / loopback deployment keeps the current behavior
// and never mismatches a client that also sends empty. TLS < 1.3 falls back to
// empty on purpose: the exporter's absent-vs-empty-context forms only agree
// cross-impl under TLS 1.3.
func (h *Handler) requestCbind(r *http.Request) ([]byte, error) {
	if r.TLS != nil {
		if r.TLS.Version < tls.VersionTLS13 {
			// Real TLS, but below 1.3. The exporter's absent-vs-empty-context
			// forms only agree cross-implementation under 1.3, so there is no
			// binding we can compute correctly here — and falling back to EMPTY
			// would silently bind a real-TLS session to nothing while the client
			// believed it was bound. Refuse instead (MYND-574 task 36).
			return nil, errNoChannelBinding
		}
		ekm, err := r.TLS.ExportKeyingMaterial(scram.ExporterLabel, nil, scram.ExporterLen)
		if err != nil {
			// Same reasoning: over real TLS, an unavailable exporter is a
			// failure, never a silent downgrade to empty.
			return nil, errNoChannelBinding
		}
		return ekm, nil
	}
	// No application-terminated TLS: a proxy terminated it, or this is loopback.
	// The application genuinely has no exporter, so it binds to the empty
	// `serverCbind` — and, because it advertises no channel binding, it also
	// accepts the honest unbound gs2 form (`n,,`) that a browser must send.
	return h.serverCbind, nil
}

// errNoChannelBinding is returned when the server terminates TLS but cannot
// produce a tls-exporter. It is never surfaced to the client as a distinct
// status — the handler answers the same 401 as any other auth failure — so it
// leaks no configuration detail.
var errNoChannelBinding = errors.New("authapi: no channel binding available over terminated TLS")

// allowUnbound reports whether this request may authenticate with the unbound
// gs2 form. True exactly when the server advertises NO channel binding: if it
// advertised `tls-exporter`, accepting `n,,` would let an attacker who strips
// the advertisement talk a bindable client out of binding.
//
// A browser is permanently in the unbound class — no browser exposes
// TLS-exporter keying material to page JavaScript — which is why the web client
// is only reachable through a deployment that does not app-terminate TLS, and
// why `threat-model.md` A4 is ⚠️ Best-effort on web rather than 🔒 Mitigated.
func (h *Handler) allowUnbound(r *http.Request) bool {
	return !h.usesTLSExporter(r)
}

// usesTLSExporter reports whether this request will bind to a real tls-exporter
// (app-terminated TLS 1.3) — the flag the init response advertises to the client.
func (h *Handler) usesTLSExporter(r *http.Request) bool {
	return r.TLS != nil && r.TLS.Version >= tls.VersionTLS13
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
	account, ok := ids.ParseAccountNumberHash(req.AccountHashHex)
	if !ok || req.ClientNonce == "" {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	sc, exists := h.creds[account]
	if !exists || sc.username != req.Username || req.Username != canonicalUsername(account) {
		// Unknown account, wrong username, and a non-canonical (e.g. raw/display-
		// form) username are all the SAME 401 — no enumeration signal (AS9: only
		// the hash-hex identity is accepted on any pre-auth surface).
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
	cbind := ""
	if h.usesTLSExporter(r) {
		cbind = scram.CbindName
	}
	writeJSON(w, scramInitResp{
		HandshakeID:   hid,
		CombinedNonce: combined,
		SaltHex:       hex.EncodeToString(sc.cred.Salt),
		Iterations:    sc.cred.Iterations,
		Cbind:         cbind,
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

	// F5: bind to THIS request's tls-exporter (app-terminated TLS 1.3) or the empty
	// h.serverCbind fallback. The client-final's connection is the one the exporter
	// is computed over on both ends, so init's connection is irrelevant to the bind.
	cbind, cbErr := h.requestCbind(r)
	if cbErr != nil {
		// Terminated TLS with no usable exporter: refuse rather than bind to
		// empty. Same 401 as any other failure — no enumeration signal.
		delete(h.hs, req.HandshakeID)
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	serverSig, bound, err := scram.VerifyClientFinalWithPolicy(
		sc.cred, hs.username, hs.clientNonce, hs.combinedNonce, cbind, h.allowUnbound(r), req.ClientFinal,
	)
	if err == nil && h.requireChannelBinding != nil && h.requireChannelBinding(hs.account) &&
		!(len(cbind) > 0 && bound) {
		// Per-account opt-out seam (MYND-577): an account that has declared
		// "bound sessions only" refuses anything else here. nil hook = feature
		// absent, which is today's state; wiring it later needs no schema change
		// and no wire change.
		//
		// The predicate is `len(cbind) > 0 && bound`, NOT `bound`. `bound`
		// means only "the client committed to the gs2 header the server
		// expected" — and when the server sits behind a terminating reverse
		// proxy it has no exporter, so `cbind` is empty and BOTH sides bind to
		// nothing while `bound` is still true. Refusing on `!bound` alone would
		// have accepted every session in exactly the deployment where no
		// channel binding exists, which is the opposite of what the opt-out is
		// for. There is really a binding only when the server had exporter
		// material to bind to.
		//
		// Corollary worth stating because it is easy to assume otherwise: this
		// can never be a web-vs-native discriminator. In a proxy-terminated
		// deployment it refuses everyone; where the server does terminate TLS
		// it admits every native client. "Refuse browser access" needs a
		// different signal.
		err = scram.ErrChannelBindMismatch
	}
	if err != nil {
		// One-shot handshake: a failed proof burns it (no online guessing reuse).
		delete(h.hs, req.HandshakeID)
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	delete(h.hs, req.HandshakeID)

	// Operator enforcement (MYND-506): a frozen account cannot mint an enrollment
	// token (blocks new devices AND pending-approval completions). Pull is unaffected
	// (a different surface). Checked after SCRAM proof so it leaks no enumeration signal.
	if h.frozen != nil && h.frozen(hs.account) {
		writeErr(w, http.StatusForbidden, "frozen")
		return
	}

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
		// New device: enforce the effective per-account device cap (MYND-506). 0 =
		// unlimited. A retired device frees its slot (CountActiveDevices excludes it).
		if h.maxDevices != nil {
			if cap := h.maxDevices(hs.account); cap > 0 && h.reg.CountActiveDevices(hs.account) >= cap {
				writeErr(w, http.StatusForbidden, "device_limit")
				return
			}
		}
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

// sessionWithCode is session() plus the reason it failed. `session` stays as the
// boolean form for the call sites that genuinely do not care, so this addition
// cannot change any of their behaviour by accident.
func (h *Handler) sessionWithCode(r *http.Request) (auth.Session, string) {
	authz := r.Header.Get("Authorization")
	const pfx = "Bearer "
	if !strings.HasPrefix(authz, pfx) {
		return auth.Session{}, "unauthenticated"
	}
	tok, err := hex.DecodeString(strings.TrimPrefix(authz, pfx))
	if err != nil {
		return auth.Session{}, "unauthenticated"
	}
	sess, err := h.tokens.AuthenticateSession(ids.DeviceToken(tok))
	if err != nil {
		return auth.Session{}, auth.FailureCode(err)
	}
	return sess, ""
}

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
	sess, authCode := h.sessionWithCode(r)
	if authCode != "" {
		writeErr(w, http.StatusUnauthorized, authCode)
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
	sess, authCode := h.sessionWithCode(r)
	if authCode != "" {
		writeErr(w, http.StatusUnauthorized, authCode)
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
	sess, authCode := h.sessionWithCode(r)
	if authCode != "" {
		writeErr(w, http.StatusUnauthorized, authCode)
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
	// Retiring the registry record IS the revocation: AuthenticateSession reads
	// that row on every request and fail-closes on it. The token binding is left
	// in place on purpose (MYND-574 task 94) — it is what lets the revoked
	// device's next request be answered `device_revoked` rather than
	// `unauthenticated`, which is the difference between "sign in again" and "the
	// account owner removed you". device_id is NOT destroyed (SYNC-2: revoking
	// never touches device_id).
	var doSave bool
	defer h.maybeSave(&doSave)
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
