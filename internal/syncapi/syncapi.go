// SPDX-License-Identifier: AGPL-3.0

// Package syncapi is the core sync loop: the authenticated push and pull endpoints
// (MYND-421). push uploads changed blobs each under a CAS base-version, then
// CAS-advances the opaque vault head (blobs-first-then-head-CAS, ledger SYNC-5).
// pull returns a paginated list of decryption-free sync_meta + the current head;
// the server selects by its own opaque change-sequence, never a wall-clock (AS6).
// Every request is session-bound (consumes the MYND-420 per-device token). The
// server is a blind relay: it never decrypts, merges, or reorders content.
package syncapi

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
	"github.com/myne-md/myne-server/internal/store"
)

// MaxBlobSize is the largest ciphertext the push path accepts: the MYA1 attachment
// cap (64 MiB) + the 32-byte CTX tag. Larger → 413 (chunked/streamed AEAD is v005).
const MaxBlobSize = 64*1024*1024 + 32

// DefaultPullLimit bounds a pull page when the client does not specify one.
const DefaultPullLimit = 256

// MaxPullLimit is the hard ceiling on a client-supplied pull page size. Without
// it a client requesting `?limit=<huge>` would materialise the whole vault's
// metas in one response (a memory spike bounded only by the account's own blob
// count); the clamp keeps a page bounded regardless of the requested value.
const MaxPullLimit = 1024

// MaxHeadRecordSize bounds the opaque vault-head record a push may carry. The
// v0.1 head is a small fixed-field record (fixed fields + a per-device version
// vector + at most two parent hashes), far below this; the cap rejects an
// oversized opaque blob that would otherwise be stored (uncounted against quota,
// §AS17) and re-sent on every pull's GetHead.
const MaxHeadRecordSize = 64 * 1024

// MaxBlobFetchIDs is the hard ceiling on the ids one POST /sync/blobs may carry.
// Unlike MaxPullLimit this REFUSES (413) rather than clamping: a clamped pull
// page still advances a cursor, so the client makes progress and comes back for
// the rest, whereas a silently truncated fetch would let a client believe it
// asked about ids it never heard back on. The client knows its own id count
// exactly, so exceeding this is a client bug and deserves to be loud.
const MaxBlobFetchIDs = 256

// MaxBlobFetchBytes bounds the raw ciphertext ONE batch response carries, measured
// before base64 (the wire body is ~4/3 of this plus ~60 B of JSON framing per
// entry, ≈11 MiB, comfortably inside the client's 64 MiB response cap). Exceeding
// it is not an error: the server serves the prefix that fits and the client
// re-requests the rest. The client cannot always plan correctly — the `size` it
// windows on is advertised by the server and untrusted, and an older server
// omits it entirely — so this bound has to be forgiving where the id count is not.
const MaxBlobFetchBytes = 8 * 1024 * 1024

// MaxBlobFetchRequestBytes bounds the batch REQUEST body. It is a list of 32-char
// hex strings, so 64 KiB holds MaxBlobFetchIDs of them with ~8× headroom — the
// push path's MaxBlobSize*4 reader would be four orders of magnitude too generous
// for a body that carries no ciphertext.
const MaxBlobFetchRequestBytes = 64 * 1024

// BlobFetchIDsPerToken is how many batched ids one rate-limit token buys, so a
// batch costs ceil(len(ids)/BlobFetchIDsPerToken) — a full MaxBlobFetchIDs window
// costs 8, and a one-id batch still costs exactly 1 (the single-blob fallback
// path's budget is unchanged). Pricing a batch at one flat token would multiply
// the per-account egress ceiling by MaxBlobFetchIDs with nothing behind it: 507
// bounds STORED bytes and has no path on a read route, so this bucket is the only
// egress bound there is. Pricing it per-id would reproduce exactly the throughput
// ceiling the batch route exists to remove. Deliberately a constant, not a config
// knob — the derivation is the documentation.
const BlobFetchIDsPerToken = 32

// RateLimiter gates requests per account (nil = disabled).
type RateLimiter interface {
	Allow(account ids.AccountNumberHash) bool
	// AllowN charges n tokens all-or-nothing, for a route whose cost scales with
	// the request rather than being flat.
	AllowN(account ids.AccountNumberHash, n uint64) bool
}

// PreAuthLimiter gates the ONE pre-auth (session-less) route this package serves —
// GET /vault.meta?account=<hex> — with a global, account-independent bucket
// (nil = disabled). It must NOT key on the attacker-supplied account query value
// or the IP (C4/AS14); see gcquota.GlobalLimiter.
type PreAuthLimiter interface {
	Allow() bool
}

// QuotaGuard reports whether storing addBytes would exceed the account ceiling
// (nil = disabled).
//
// Store-AGNOSTIC since #8: the caller supplies the current byte total, because
// the ceiling is defined against blobs PLUS attachments and only the
// composition layer can see both. The old `WouldExceed(store, …)` shape took
// the blob store and resolved "current" from it alone, which is precisely how
// this route came to enforce a different ceiling than the attachment route and
// /account/status reported.
type QuotaGuard interface {
	WouldExceedTotalForAccount(account ids.AccountNumberHash, currentBytes, addBytes uint64) bool
}

// Notifier receives a contentless "changed" signal after a successful push (nil =
// disabled). The signal carries only the account — no note-id/version/count (A13).
type Notifier interface {
	Notify(account ids.AccountNumberHash)
}

// Handler serves /sync/push and /sync/pull.
type Handler struct {
	store       store.BlobStore
	auth        *auth.TokenStore
	rl          RateLimiter    // optional (MYND-422)
	qg          QuotaGuard     // optional (MYND-422)
	notifier    Notifier       // optional (MYND-423 poke)
	onStored    func(int)      // optional aggregate metric hook (MYND-440); n bytes per stored blob
	metaLimiter PreAuthLimiter // optional global limiter for the pre-auth vault.meta GET
	// attachmentDeleter marks the stored attachment BODY deleted when an
	// attachment tombstone record lands (MYND-468, §11.4 step 2) — the bridge to
	// the attachments store, injected as a closure so the packages stay decoupled.
	// nil = no attachment store wired (tests that only exercise notes).
	attachmentDeleter func(account ids.AccountNumberHash, id [32]byte)
	// activityTouch records that a device made an authed sync request, feeding the
	// horizon-GC soft-retire (MYND-422): a long-silent device drops out of the
	// must-ack set so tombstone reclaim can proceed. Injected as a closure over the
	// auth registry + the shared day-bucket marker so this package stays decoupled
	// from auth.Registry. nil = no activity tracking wired (notes-only tests).
	activityTouch func(account ids.AccountNumberHash, dev ids.DeviceID)
	// frozen reports whether an account is operator-frozen (MYND-506): a frozen
	// account's PUSH is refused, but PULL is never blocked (data is never held
	// hostage — the "frozen is minimal" invariant). Injected as a closure over the
	// accounts store so this package stays decoupled. nil = no freeze wired.
	frozen func(account ids.AccountNumberHash) bool
	// accountStatus returns the caller's own status projection (stored bytes, device
	// count, frozen, effective ceilings) for GET /account/status. The account is the
	// authenticated one, plus the vaults it owns when it is a person session
	// (myne-md/myne#911 task 11); nil = the endpoint reports unavailable.
	accountStatus func(scope StatusScope) any
	// usedBytes is the UNIFIED per-account stored-byte total — blobs plus
	// attachments — the AS17 ceiling is defined against (#8).
	//
	// The push gate used to resolve "current" from the blob store alone, while
	// the attachment gate and GET /account/status both counted the unified
	// figure. So an account whose attachments already filled the quota could
	// keep pushing note blobs past a ceiling its own status endpoint reported
	// as full, and the operator's number disagreed with the enforcement.
	// nil = fall back to the blob-only figure (notes-only tests).
	usedBytes func(account ids.AccountNumberHash) uint64
	// membership authorizes the B2B vault-scoped routes and gates the vault.meta
	// write (myne-md/myne#711): a vault that has an owner binding requires the
	// owner's per-vault token. nil = B2B not wired, so vault.meta keeps the
	// pre-B2B device-token path and the retire route is refused.
	membership MembershipAuth
	// retirements is the namespace-retirement registry (nil = not wired).
	retirements *store.Retirements
}

// MembershipAuth is the B2B membership authority as the sync surface needs it.
// It is an interface so this package does not import the HTTP auth surface; the
// handler is wired in the composition layer. ResolveMember answers "is this
// per-vault bearer token valid, for which vault, and is it the owner's".
type MembershipAuth interface {
	ResolveMember(bearerHex string) (b membership.Binding, ok bool)
	// DeviceActive reports whether `device` is still an active, approved device of
	// the ACCOUNT it is registered under (myne-md/myne#911 task 9). A membership
	// token names the device it was issued to, so the ONE act that revokes a device
	// also ends its access to every shared vault it joined: this is asked on every
	// request rather than swept at revoke time, so a token cannot outlive its
	// device.
	//
	// `account` is the SCRAM account the token was issued under, NOT the person
	// holding the binding: the registry is keyed by account, and a shared vault's
	// owner binding is minted by the VAULT's own device session, so asking about the
	// person is asking about an account the registry has never held
	// (myne-md/myne#911 follow-up).
	//
	// A token with no device or no account (issued before those fields existed) is
	// never refused by this check: it cannot be attributed, and guessing would
	// revoke somebody else's access.
	DeviceActive(account ids.AccountNumberHash, device ids.DeviceID) bool
	HasOwner(vault ids.AccountNumberHash) bool
	// BoundTo reports whether `person` holds a binding to `vault` (myne-md/myne#911
	// task 7). It is the ONE new authority this feature adds to the sync surface:
	// a person session may act on a vault it is bound to, and on nothing else.
	//
	// `person` is an account id, because the server cannot tell a person id from a
	// vault id and does not try (server-protocol §3.1a). A vault's own device
	// account is not bound to itself, so this answers false for it, which is why
	// the resolver below checks the equality case FIRST and never reaches here for
	// a vault acting on its own namespace.
	BoundTo(vault ids.AccountNumberHash, person ids.AccountNumberHash) (owner bool, ok bool)
	// BindOwner records the vault's owner. Publishing a vault under a person
	// session is owner-at-first-write (§3.1a's rule), so the sync surface needs
	// exactly this one mutator and no other membership write.
	BindOwner(vault ids.AccountNumberHash, person ids.AccountNumberHash) error
	// OwnedVaults reports the vaults `person` OWNS (myne-md/myne#911 task 11). It
	// is what lets GET /account/status answer with ONE usage figure for a person
	// account: the aggregate is the sum of those vaults' byte counters.
	//
	// OWned only, deliberately. A vault the person merely JOINED holds somebody
	// else's bytes and the member cannot free them, so counting them would report
	// usage the person cannot act on. An account with no owned vaults answers
	// empty, which is also how the status route tells a person session from a
	// vault session without a second identity flag: a vault's own account is
	// bound to nothing.
	OwnedVaults(person ids.AccountNumberHash) []ids.AccountNumberHash
}

// WithMembership installs the B2B membership seam (myne-md/myne#711). It gates
// the vault.meta write on the owner's per-vault token and authorizes retire.
func (h *Handler) WithMembership(m MembershipAuth) *Handler {
	h.membership = m
	return h
}

// WithRetirements installs the namespace-retirement registry. Without it the
// retire route reports unauthenticated and no push is refused for retirement.
func (h *Handler) WithRetirements(r *store.Retirements) *Handler {
	h.retirements = r
	return h
}

// New returns a sync Handler over the given store + token store.
func New(s store.BlobStore, ts *auth.TokenStore) *Handler {
	return &Handler{store: s, auth: ts}
}

// WithFrozenCheck installs the operator-freeze predicate (MYND-506). It gates PUSH
// only; pull deliberately never consults it.
func (h *Handler) WithFrozenCheck(fn func(account ids.AccountNumberHash) bool) *Handler {
	h.frozen = fn
	return h
}

// WithAccountStatus installs the GET /account/status projection (MYND-506). fn is
// invoked with the AUTHENTICATED account (never a URL/query value), and with the
// vaults that account owns when it is a person session (myne-md/myne#911 task 11),
// so one projection can answer both scopes.
func (h *Handler) WithAccountStatus(fn func(scope StatusScope) any) *Handler {
	h.accountStatus = fn
	return h
}

// StatusScope is what GET /account/status is asked about.
//
// The account always comes from the token; `Vaults` is populated only for a
// person session that owns at least one vault, and it is the ONE input that makes
// the difference between "this vault's usage" and "this account's usage". It is a
// struct rather than a second parameter so a caller cannot pass the vault list
// while forgetting which account it belongs to.
type StatusScope struct {
	// Account is the token-resolved account: a vault's account hash for a vault
	// session, the person id for a person session (the server cannot tell the two
	// apart, §3.1a, and does not try).
	Account ids.AccountNumberHash
	// Vaults are the vaults `Account` OWNS. Empty for a vault session and for a
	// person who owns nothing, which is why `Person` is a separate bit rather
	// than `len(Vaults) > 0`: the projection must be able to say "this is an
	// account total over zero vaults" rather than "this is a vault".
	Vaults []ids.AccountNumberHash
	// Person reports that the caller is a person session (the membership table
	// has an owner binding naming this account). A person's own namespace holds
	// no blobs, so a projection that ignored this bit would report zero bytes for
	// an account with ten full vaults.
	Person bool
}

// WithUsedBytes injects the UNIFIED per-account stored-byte total the quota gate
// is defined against — blobs plus attachments (#8).
//
// A closure rather than a second store handle so this package stays decoupled;
// the composition layer already builds exactly this function once, for
// /account/status and the operator admin API, so all three read one definition.
func (h *Handler) WithUsedBytes(fn func(account ids.AccountNumberHash) uint64) *Handler {
	h.usedBytes = fn
	return h
}

// WithPolicy attaches the MYND-422 rate-limiter + quota guard. Either may be nil.
func (h *Handler) WithPolicy(rl RateLimiter, qg QuotaGuard) *Handler {
	h.rl = rl
	h.qg = qg
	return h
}

// WithNotifier attaches the MYND-423 change-notifier (poked after a successful push).
func (h *Handler) WithNotifier(n Notifier) *Handler {
	h.notifier = n
	return h
}

// WithPreAuthLimiter attaches the global pre-auth limiter guarding the vault.meta
// GET bootstrap (nil = disabled).
func (h *Handler) WithPreAuthLimiter(g PreAuthLimiter) *Handler {
	h.metaLimiter = g
	return h
}

// WithAttachmentDeleter attaches the attachments-store bridge (MYND-468): called
// with the full attachment-id when an attachment tombstone record lands, so the
// body reads as absent from then on (physical reclaim rides horizon-GC).
func (h *Handler) WithAttachmentDeleter(fn func(account ids.AccountNumberHash, id [32]byte)) *Handler {
	h.attachmentDeleter = fn
	return h
}

// WithActivityTouch attaches the per-request activity recorder (F4): called on
// every authed pull/push so the horizon-GC knows a device is still active. Wiring
// it is what makes soft-retire actually fire — without it every device sits at
// LastActivity 0 forever and tombstone ciphertext never gets reclaimed. nil = off.
func (h *Handler) WithActivityTouch(fn func(account ids.AccountNumberHash, dev ids.DeviceID)) *Handler {
	h.activityTouch = fn
	return h
}

// touchActivity records an authed sync touch if the recorder is wired (no-op
// otherwise). Any authed pull/push counts as activity.
func (h *Handler) touchActivity(account ids.AccountNumberHash, dev ids.DeviceID) {
	if h.activityTouch != nil {
		h.activityTouch(account, dev)
	}
}

// WithMetrics attaches an aggregate-only observation hook (MYND-440, SYNC-24):
// onStored is called with the byte length of each successfully stored blob. It
// carries NO account/IP — it feeds the aggregate `myne_blobs_stored_total` /
// `myne_bytes_stored_total` counters only.
func (h *Handler) WithMetrics(onStored func(int)) *Handler {
	h.onStored = onStored
	return h
}

// Register wires the sync routes onto a mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/sync/push", h.handlePush)
	mux.HandleFunc("/sync/pull", h.handlePull)
	mux.HandleFunc("/sync/blob", h.handleBlob)
	mux.HandleFunc("/sync/blobs", h.handleBlobs)
	mux.HandleFunc("/vault.meta", h.handleMeta)
	mux.HandleFunc("/account/status", h.handleAccountStatus)
	// Owner-only namespace retirement (myne-md/myne#711, decisions/protocol/0599).
	mux.HandleFunc("POST /b2b/vaults/{account_hash}/retire", h.handleRetire)
}

// --- wire types ---

type pushBlob struct {
	BlobIDHex     string `json:"blob_id_hex"`
	BaseVersion   uint64 `json:"base_version"`
	ContentNonce  string `json:"content_nonce_hex"`
	CiphertextB64 string `json:"ciphertext_b64"`
	// Tombstone marks this push as a deletion (a deleted-marked version). The server
	// records the (uuid, final_version, marker) for horizon-GC; it never learns
	// "deleted" meaning beyond that (AS6). The ciphertext is still opaque.
	Tombstone bool `json:"tombstone,omitempty"`
	// AttachmentIDHex (MYND-468, sync-protocol §8.1/§11.4) marks this record as an
	// ATTACHMENT: blob_id_hex is the id's first 16 bytes, ciphertext_b64 is empty
	// (the bytes travelled over /attachments/{id}), and this field carries the full
	// 32-byte id (64 hex). On a tombstone push the server additionally marks the
	// stored attachment body deleted. Absent for notes.
	AttachmentIDHex string `json:"attachment_id_hex,omitempty"`
}

type pushHead struct {
	PrevHeadHashHex string `json:"prev_head_hash_hex"`
	RecordB64       string `json:"record_b64"`
}

type pushReq struct {
	Blobs   []pushBlob `json:"blobs"`
	NewHead *pushHead  `json:"new_head,omitempty"`
}

type pushResult struct {
	BlobIDHex string `json:"blob_id_hex"`
	Version   uint64 `json:"version"`
}

type pushResp struct {
	Results   []pushResult `json:"results"`
	HeadIDHex string       `json:"head_id_hex,omitempty"`
}

type syncMetaWire struct {
	UUIDHex      string `json:"uuid_hex"`
	Version      uint64 `json:"version"`
	ContentNonce string `json:"content_nonce_hex"`
	Size         int    `json:"size"`
	// AttachmentIDHex echoes the full attachment-id back for an attachment record
	// (MYND-468) so a puller resolves the 16-byte prefix without the catalog.
	AttachmentIDHex string `json:"attachment_id_hex,omitempty"`
}

type headWire struct {
	RecordB64 string `json:"record_b64"`
	HeadIDHex string `json:"head_id_hex"`
}

type pullResp struct {
	Metas      []syncMetaWire `json:"metas"`
	NextCursor uint64         `json:"next_cursor"`
	Head       *headWire      `json:"head,omitempty"`
}

// blobResp is the GET /sync/blob body: the opaque ciphertext + its version. The
// client downloads a changed blob's bytes after /sync/pull lists its meta
// (MYND-424 download path; the store has the bytes, this route exposes them).
type blobResp struct {
	CiphertextB64 string `json:"ciphertext_b64"`
	Version       uint64 `json:"version"`
}

// blobsReq is the POST /sync/blobs body: the ids to fetch, in the order the
// client wants them accounted for.
type blobsReq struct {
	BlobIDsHex []string `json:"blob_ids_hex"`
}

// blobEntry is one served ciphertext. No `version` field, deliberately: the
// single-blob route carries one and no client reads it, because the version a
// puller adopts comes from the pull meta whose content_nonce it verified.
// Shipping a second, differently-sourced version here would invite a future
// reader to adopt it and silently move the CAS base.
type blobEntry struct {
	BlobIDHex     string `json:"blob_id_hex"`
	CiphertextB64 string `json:"ciphertext_b64"`
}

// blobOmitted is one id the server accounted for but did not serve, carrying the
// SAME error_code strings the single-blob route emits as statuses. This array is
// load-bearing, not cosmetic: a reclaimed record must never come back as an entry
// with an empty ciphertext_b64, because a blind client cannot tell that from real
// bytes and would write 0 bytes over a live note (§11.3, the reason the single
// route is 410 rather than an empty 200).
type blobOmitted struct {
	BlobIDHex string `json:"blob_id_hex"`
	ErrorCode string `json:"error_code"`
}

// blobsResp accounts for a PREFIX of the requested ids, in request order: every
// id it reached appears in exactly one of the two arrays, and an id in neither
// was not served — the client re-requests it. That is what lets the byte budget
// truncate safely without the client having to guess right.
type blobsResp struct {
	Blobs   []blobEntry   `json:"blobs"`
	Omitted []blobOmitted `json:"omitted"`
}

// errBody is the thin machine-readable error envelope (SYNC-6). The HTTP status is
// the coarse signal; error_code disambiguates (e.g. blob_stale vs head_stale 409).
type errBody struct {
	ErrorCode string `json:"error_code"`
}

// errPushHandled ends handlePush's store batch from inside the closure after the
// closure has already written the client's response (400/409/413/507/500). It never
// reaches the client — it only tells the code after the batch that the response is
// written, so it cannot double-write one. Not an errors.Is target for callers.
var errPushHandled = errors.New("syncapi: push response already written")

// handleAccountStatus serves GET /account/status: the caller's own enforcement-state
// projection (MYND-506). The account is resolved from the DEVICE TOKEN — never from
// the URL or query, so the account number never appears in a request line or log. An
// identifier a client places in the URL/query is ignored (never a selector).
func (h *Handler) handleAccountStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	sess, authCode := h.sessionWithCode(r)
	if authCode != "" {
		writeErr(w, http.StatusUnauthorized, authCode)
		return
	}
	if h.rl != nil && !h.rl.Allow(sess.Account) {
		writeErr(w, http.StatusTooManyRequests, "rate")
		return
	}
	if h.accountStatus == nil {
		writeErr(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	// The person arm (myne-md/myne#911 task 11): one usage figure for the account
	// rather than one per vault. A person session owns vaults; a vault session owns
	// none, which is what makes this answer a fact rather than a guess. The person
	// ceiling this reports is NOT enforced (§5.1): the push guard reads the vault's
	// own ceiling, because a person's namespace holds no blobs to count.
	scope := StatusScope{Account: sess.Account}
	if h.membership != nil {
		scope.Vaults = h.membership.OwnedVaults(sess.Account)
		scope.Person = len(scope.Vaults) > 0
	}
	writeJSON(w, h.accountStatus(scope))
}

func writeErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errBody{ErrorCode: code})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

// sessionWithCode is session() plus the reason it failed. `session` stays as the
// boolean form for the call sites that genuinely do not care, so this addition
// cannot change any of their behaviour by accident.
func (h *Handler) sessionWithCode(r *http.Request) (auth.Session, string) {
	authz := r.Header.Get("Authorization")
	const pfx = "Bearer "
	if !strings.HasPrefix(authz, pfx) {
		return auth.Session{}, "unauthenticated"
	}
	hexTok := strings.TrimPrefix(authz, pfx)
	tok, err := hex.DecodeString(hexTok)
	if err != nil {
		return auth.Session{}, "unauthenticated"
	}
	sess, err := h.auth.AuthenticateSession(ids.DeviceToken(tok))
	if err == nil {
		return sess, ""
	}
	// B2B member (myne-md/myne#711): a per-vault MEMBERSHIP token authorizes the
	// vault's sync namespace, so a member with no account of its own can read and
	// write shared content. The vault.meta write gate (retire.go) still refuses a
	// member token for the credential blob. The membership token carries no
	// device id, so member cursors share the zero device slot; that only costs a
	// re-pull and never a wrong read.
	if h.membership != nil {
		if b, ok := h.membership.ResolveMember(hexTok); ok {
			// One revocation covers every vault (myne-md/myne#911 task 9): the
			// token still resolves (its binding stands), but the device it was
			// issued to is gone, so every request it makes is refused the same way
			// a revoked DEVICE token is. `device_revoked` rather than
			// `unauthenticated` keeps the client from re-enrolling into an account
			// whose owner removed it.
			if b.Device != (ids.DeviceID{}) && b.Account != (ids.AccountNumberHash{}) && !h.membership.DeviceActive(b.Account, ids.DeviceID(b.Device)) {
				return auth.Session{}, "device_revoked"
			}
			return auth.Session{Account: b.Vault}, ""
		}
	}
	return auth.Session{}, auth.FailureCode(err)
}

// session extracts + validates the bearer token, returning the bound session.
func (h *Handler) session(r *http.Request) (auth.Session, bool) {
	sess, code := h.sessionWithCode(r)
	return sess, code == ""
}

// requestedNamespace reads the optional `?account=<hex>` selector.
//
// Present only on a PERSON session: a member's per-vault token and a vault's own
// device token already carry their namespace, and neither needs to name one. It
// is ABSENT on every pre-existing call, which is what keeps the legacy wire byte
// identical (myne-md/myne#911 task 7).
//
// A malformed value is a client error rather than an ignored parameter: silently
// falling back to the bearer's own namespace would turn a typo into a write to
// the wrong vault.
func requestedNamespace(r *http.Request) (ids.AccountNumberHash, bool, bool) {
	raw := r.URL.Query().Get("account")
	if raw == "" {
		return ids.AccountNumberHash{}, false, true
	}
	vault, ok := ids.ParseAccountNumberHash(raw)
	return vault, true, ok
}

// namespaceRefusalStatus maps a `namespaceSession` code to its HTTP status.
//
// The codes are the same closed set the sync surface already speaks; only the
// status differs, and a refusal that is about AUTHORITY (403) must not be
// reported as a refusal about IDENTITY (401): a client that reads 401 as "my
// token died" would re-enrol on a request that was correctly refused.
func namespaceRefusalStatus(code string) int {
	switch code {
	case "forbidden":
		return http.StatusForbidden
	case "bad_request":
		return http.StatusBadRequest
	default:
		return http.StatusUnauthorized
	}
}

// namespaceSession is sessionWithCode plus the person-selector rule.
//
// Three cases, in this order, and the order is the security property:
//
//  1. No selector: exactly the pre-task-7 behaviour, so every existing client
//     and every legacy token (vault device token, per-vault membership token)
//     is authorized by the same code path it always was.
//  2. Selector equal to the session's own account: the vault's own device token
//     naming itself. Authorized without a membership lookup, because a vault
//     does not need a binding to its own namespace (and could not have one: the
//     owner binding names a PERSON).
//  3. Selector different from the session's account: the session is treated as a
//     PERSON, and the request is authorized only when that person is bound to the
//     requested vault. An unbound selector is REFUSED, never quietly
//     reinterpreted as the caller's own namespace; that refusal is the whole
//     difference between an availability control and a cross-vault read/write.
func (h *Handler) namespaceSession(r *http.Request) (auth.Session, string) {
	sess, code := h.sessionWithCode(r)
	if code != "" {
		return auth.Session{}, code
	}
	vault, hasSelector, ok := requestedNamespace(r)
	if !hasSelector {
		return sess, ""
	}
	if !ok {
		return auth.Session{}, "bad_request"
	}
	if vault == sess.Account {
		return sess, ""
	}
	if h.membership == nil {
		return auth.Session{}, "forbidden"
	}
	if _, bound := h.membership.BoundTo(vault, sess.Account); !bound {
		return auth.Session{}, "forbidden"
	}
	// The device slot is the person's own: cursors are per (namespace, device),
	// and a person driving two vaults must not share one cursor across them.
	return auth.Session{Account: vault, Device: sess.Device}, ""
}

func parseBlobID(s string) (ids.BlobID, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ids.BlobIDLen {
		return ids.BlobID{}, false
	}
	var id ids.BlobID
	copy(id[:], b)
	return id, true
}

func parseNonce(s string) ([store.ContentNonceLen]byte, bool) {
	var n [store.ContentNonceLen]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != store.ContentNonceLen {
		return n, false
	}
	copy(n[:], b)
	return n, true
}

func (h *Handler) handlePush(w http.ResponseWriter, r *http.Request) {
	// The namespace is the bearer's own unless a person session names
	// one (`?account=`, task 7); see `namespaceSession`.
	sess, nsCode := h.namespaceSession(r)
	if nsCode != "" {
		writeErr(w, namespaceRefusalStatus(nsCode), nsCode)
		return
	}

	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	if h.rl != nil && !h.rl.Allow(sess.Account) {
		writeErr(w, http.StatusTooManyRequests, "rate")
		return
	}
	// A frozen account cannot push (MYND-506) — pull stays open (handlePull never
	// consults this). Checked before recording activity so a refused push is a no-op.
	if h.frozen != nil && h.frozen(sess.Account) {
		writeErr(w, http.StatusForbidden, "frozen")
		return
	}
	// An authed push is device activity — feed the horizon-GC soft-retire (F4).
	h.touchActivity(sess.Account, sess.Device)
	var req pushReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBlobSize*4)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}

	// Every mutation this request performs runs inside ONE store batch, so a
	// backend that writes per-vault bookkeeping per mutation writes it once for
	// the whole request instead of once per blob (myne-server#6: a 50k-blob push
	// was quadratic and never returned). Semantics are unchanged — the batch is a
	// durability-granularity scope, not a transaction, so the CAS abort below
	// still leaves the already-stored prefix stored.
	var resp pushResp
	berr := h.store.Batch(sess.Account, func() error {
		// Blobs-first: store each content-addressed blob under CAS (SYNC-5).
		results := make([]pushResult, 0, len(req.Blobs))
		for _, b := range req.Blobs {
			id, idOK := parseBlobID(b.BlobIDHex)
			nonce, nOK := parseNonce(b.ContentNonce)
			ct, err := base64.StdEncoding.DecodeString(b.CiphertextB64)
			if !idOK || !nOK || err != nil {
				writeErr(w, http.StatusBadRequest, "bad_request")
				return errPushHandled
			}
			// A retired namespace may not be written again (myne-md/myne#711):
			// the owner rotated away from it, and a stale device must not
			// resurrect it. Reclamation is separate and grace-bounded.
			if h.retirements != nil && h.retirements.IsRetired(sess.Account, id) {
				writeErr(w, http.StatusConflict, "retired")
				return errPushHandled
			}
			// An attachment record (MYND-468): validate the full id and its prefix
			// relation to the record key BEFORE storing anything.
			var attID [32]byte
			isAttachment := b.AttachmentIDHex != ""
			if isAttachment {
				ab, aerr := hex.DecodeString(b.AttachmentIDHex)
				if aerr != nil || len(ab) != 32 {
					writeErr(w, http.StatusBadRequest, "bad_request")
					return errPushHandled
				}
				copy(attID[:], ab)
				if string(attID[:ids.BlobIDLen]) != string(id[:]) {
					// The record key MUST be the id's first 16 bytes (§4.2 pin).
					writeErr(w, http.StatusBadRequest, "bad_request")
					return errPushHandled
				}
			}
			if len(ct) > MaxBlobSize {
				writeErr(w, http.StatusRequestEntityTooLarge, "too_large")
				return errPushHandled
			}
			// #8: gate on the UNIFIED total, the same figure the attachment
			// route and /account/status use. Without this the ceiling was
			// per-subsystem in one direction only.
			if h.qg != nil {
				current := h.store.QuotaBytes(sess.Account)
				if h.usedBytes != nil {
					current = h.usedBytes(sess.Account)
				}
				// #10: charge the push its GROWTH, not its full size. Storing this
				// blob REPLACES the bytes it holds now, and both backends account
				// for exactly that delta — charging the whole ciphertext made the
				// gate stricter than the counter it guards. At the ceiling that
				// refused a shrink, and refused a deletion too (the tombstone blob
				// is the note plus a `deleted:` line, so it is LARGER than the
				// version it replaces); since bytes are freed only by horizon-GC
				// reclaiming a tombstone, the account could then never free
				// anything again. Growth past the ceiling is still refused.
				add := uint64(len(ct))
				if stored := h.store.BlobQuotaBytes(sess.Account, id); stored < add {
					add -= stored
				} else {
					add = 0
				}
				if h.qg.WouldExceedTotalForAccount(sess.Account, current, add) {
					writeErr(w, http.StatusInsufficientStorage, "quota")
					return errPushHandled
				}
			}
			ver, perr := h.store.PushBlob(sess.Account, id, store.Version(b.BaseVersion), nonce, ct)
			if errors.Is(perr, store.ErrBlobCASMismatch) {
				writeErr(w, http.StatusConflict, "blob_stale")
				return errPushHandled
			}
			if perr != nil {
				writeErr(w, http.StatusInternalServerError, "internal")
				return errPushHandled
			}
			if h.onStored != nil {
				h.onStored(len(ct)) // aggregate metric only — no account/IP (MYND-440)
			}
			if isAttachment {
				// Persist the prefix→full-id association: pull echoes it, GC bridges it.
				_ = h.store.SetBlobAttachmentID(sess.Account, id, b.AttachmentIDHex)
			}
			if b.Tombstone {
				// Record the (uuid, final_version, marker) for horizon-GC (MYND-422).
				_ = h.store.SetTombstone(sess.Account, id, ver)
				if isAttachment && h.attachmentDeleter != nil {
					// §11.4 step 2: the stored attachment BODY reads as absent from
					// now on; physical reclaim rides the record's horizon-GC.
					h.attachmentDeleter(sess.Account, attID)
				}
			}
			results = append(results, pushResult{BlobIDHex: b.BlobIDHex, Version: uint64(ver)})
		}

		// Then CAS-advance the head, if supplied.
		resp = pushResp{Results: results}
		if req.NewHead != nil {
			prev, perr := hex.DecodeString(req.NewHead.PrevHeadHashHex)
			rec, rerr := base64.StdEncoding.DecodeString(req.NewHead.RecordB64)
			if perr != nil || rerr != nil || len(prev) != store.HeadIDLen {
				writeErr(w, http.StatusBadRequest, "bad_request")
				return errPushHandled
			}
			if len(rec) > MaxHeadRecordSize {
				writeErr(w, http.StatusRequestEntityTooLarge, "too_large")
				return errPushHandled
			}
			var prevArr [store.HeadIDLen]byte
			copy(prevArr[:], prev)
			newID, herr := h.store.AdvanceHead(sess.Account, prevArr, rec)
			if errors.Is(herr, store.ErrHeadCASMismatch) {
				writeErr(w, http.StatusConflict, "head_stale")
				return errPushHandled
			}
			if herr != nil {
				writeErr(w, http.StatusInternalServerError, "internal")
				return errPushHandled
			}
			resp.HeadIDHex = hex.EncodeToString(newID[:])
		}
		return nil
	})
	if errors.Is(berr, errPushHandled) {
		return // the closure already wrote the response
	}
	if berr != nil {
		// The batch's coalesced bookkeeping write failed. Reporting it is only
		// possible because the success response is written out here rather than
		// inside the closure — per-mutation persistence had no such point and
		// answered 200 to a push whose index never reached disk.
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	// Contentless poke to the account's SSE subscribers (zero-payload, A13).
	if h.notifier != nil && (len(req.Blobs) > 0 || req.NewHead != nil) {
		h.notifier.Notify(sess.Account)
	}
	writeJSON(w, resp)
}

func (h *Handler) handlePull(w http.ResponseWriter, r *http.Request) {
	// The namespace is the bearer's own unless a person session names
	// one (`?account=`, task 7); see `namespaceSession`.
	sess, nsCode := h.namespaceSession(r)
	if nsCode != "" {
		writeErr(w, namespaceRefusalStatus(nsCode), nsCode)
		return
	}

	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	if h.rl != nil && !h.rl.Allow(sess.Account) {
		writeErr(w, http.StatusTooManyRequests, "rate")
		return
	}
	cursor, _ := strconv.ParseUint(r.URL.Query().Get("cursor"), 10, 64)
	limit := DefaultPullLimit
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 {
		limit = l
	}
	if limit > MaxPullLimit {
		limit = MaxPullLimit
	}
	// A reconcile-mode pull (`?reconcile=1`) is the client walking the WHOLE
	// manifest from cursor 0 and diffing it against local state (§11.2). That walk
	// reconstructs deletions from manifest-absence, so it needs no replayable
	// tombstone history and is exempt from the cursor-expired floor below.
	reconcile := r.URL.Query().Get("reconcile") == "1"

	// Cursor-expired: a non-zero cursor below the GC reclaim floor missed reclaimed
	// history → force §11.2 full-reconcile (ledger SYNC-6). Skipped for a reconcile
	// pull, which is ALREADY doing that full walk: without this exemption a vault
	// with more than one page (DefaultPullLimit) of live blobs whose reclaim floor
	// sits beyond the first page boundary wedges any re-paginating device — page 1
	// hands back a next_cursor below the floor, and the page-2 pull at that cursor
	// is rejected as cursor_expired, so the reconcile can never drain past the floor.
	if !reconcile && cursor > 0 && cursor < h.store.GCFloor(sess.Account) {
		writeErr(w, http.StatusGone, "cursor_expired")
		return
	}

	metas, next := h.store.ChangedSince(sess.Account, cursor, limit)
	// Record the device's cursor ack (the must-ack signal MYND-422 aggregates).
	h.store.AckCursor(sess.Account, sess.Device, cursor)
	// An authed pull is device activity — feed the horizon-GC soft-retire (F4).
	h.touchActivity(sess.Account, sess.Device)

	resp := pullResp{NextCursor: next, Metas: make([]syncMetaWire, 0, len(metas))}
	for _, m := range metas {
		resp.Metas = append(resp.Metas, syncMetaWire{
			UUIDHex:         hex.EncodeToString(m.BlobID[:]),
			Version:         uint64(m.Version),
			ContentNonce:    hex.EncodeToString(m.ContentNonce[:]),
			Size:            m.Size,
			AttachmentIDHex: m.AttachmentIDHex,
		})
	}
	if rec, headID, err := h.store.GetHead(sess.Account); err == nil {
		resp.Head = &headWire{RecordB64: base64.StdEncoding.EncodeToString(rec), HeadIDHex: hex.EncodeToString(headID[:])}
	}
	writeJSON(w, resp)
}

// handleBlob serves GET /sync/blob?id=<hex>: the opaque ciphertext for one blob
// the client learned about via /sync/pull's metas. Session-bound, rate-limited,
// per-account namespaced (the blob is looked up under the session's account).
// Blind relay — the server never inspects the ciphertext.
func (h *Handler) handleBlob(w http.ResponseWriter, r *http.Request) {
	// The namespace is the bearer's own unless a person session names
	// one (`?account=`, task 7); see `namespaceSession`.
	sess, nsCode := h.namespaceSession(r)
	if nsCode != "" {
		writeErr(w, namespaceRefusalStatus(nsCode), nsCode)
		return
	}

	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	if h.rl != nil && !h.rl.Allow(sess.Account) {
		writeErr(w, http.StatusTooManyRequests, "rate")
		return
	}
	id, idOK := parseBlobID(r.URL.Query().Get("id"))
	if !idOK {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	ct, ver, err := h.store.GetBlob(sess.Account, id)
	// A Layer-2 reclaimed blob is fail-closed 410 (§11.3): a 200 with an empty
	// body would read as a live zero-byte ciphertext and the puller would
	// overwrite a real note with it. 410 (vs 404) tells the client this uuid
	// once existed and was reclaimed — drop/quarantine, don't re-push.
	if errors.Is(err, store.ErrReclaimed) {
		writeErr(w, http.StatusGone, "blob_reclaimed")
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, blobResp{
		CiphertextB64: base64.StdEncoding.EncodeToString(ct),
		Version:       uint64(ver),
	})
}

// handleBlobs serves POST /sync/blobs: up to MaxBlobFetchIDs opaque ciphertexts
// in ONE request, the read-path twin of the chunked push (myne-md/myne#240). The
// pull path was one HTTP request per blob, so a first sync of a large vault spent
// its whole cost in round-trips against the per-account bucket rather than in
// bandwidth. Blind relay throughout — the server never inspects a ciphertext.
//
// The spine is handleBlob's, in the same order (method → session → rate limit →
// parse → store), with two deliberate divergences:
//
//   - No frozen gate. Reads are never refused; handleBlob and handlePull both
//     omit it and this must match them, not handlePush.
//   - No touchActivity. handleBlob does not touch either, and a batch fetch
//     always follows a pull in the same cycle, which already did.
//
// Per-id outcomes are fail-closed the way §11.3 requires: a reclaimed or unknown
// id is reported by OMISSION FROM THE PAYLOAD plus an explicit code, never as an
// entry with empty bytes.
func (h *Handler) handleBlobs(w http.ResponseWriter, r *http.Request) {
	// The namespace is the bearer's own unless a person session names
	// one (`?account=`, task 7); see `namespaceSession`.
	sess, nsCode := h.namespaceSession(r)
	if nsCode != "" {
		writeErr(w, namespaceRefusalStatus(nsCode), nsCode)
		return
	}

	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
		return
	}
	if h.rl != nil && !h.rl.AllowN(sess.Account, 1) {
		writeErr(w, http.StatusTooManyRequests, "rate")
		return
	}
	var req blobsReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBlobFetchRequestBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	if len(req.BlobIDsHex) > MaxBlobFetchIDs {
		writeErr(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}
	if cost := uint64(len(req.BlobIDsHex)+BlobFetchIDsPerToken-1) / BlobFetchIDsPerToken; h.rl != nil && cost > 1 {
		if !h.rl.AllowN(sess.Account, cost-1) {
			writeErr(w, http.StatusTooManyRequests, "rate")
			return
		}
	}
	// A malformed id fails the WHOLE request rather than becoming a per-id
	// omission: it is a client bug, and answering it per-id would let a client
	// mistake "you sent me garbage" for "the server does not have this".
	fetch := make([]ids.BlobID, 0, len(req.BlobIDsHex))
	for _, s := range req.BlobIDsHex {
		id, ok := parseBlobID(s)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad_request")
			return
		}
		fetch = append(fetch, id)
	}

	resp := blobsResp{Blobs: []blobEntry{}, Omitted: []blobOmitted{}}
	bytesSoFar := 0
	for i, id := range fetch {
		// Echo the CANONICAL lowercase hex of the parsed id, not the client's raw
		// string: hex decoding accepts either case, and a response that mirrors
		// the request's casing would make the client's id lookup depend on what
		// it happened to send.
		idHex := hex.EncodeToString(id[:])
		ct, _, err := h.store.GetBlob(sess.Account, id)
		switch {
		case errors.Is(err, store.ErrReclaimed):
			// Never an entry with empty bytes — see the type doc on blobOmitted.
			resp.Omitted = append(resp.Omitted, blobOmitted{BlobIDHex: idHex, ErrorCode: "blob_reclaimed"})
		case errors.Is(err, store.ErrNotFound):
			// Also the answer for an id belonging to ANOTHER account: the store is
			// namespaced per account, so a cross-account id is simply absent here.
			// It must not be blob_reclaimed, which would confirm the id exists
			// somewhere.
			resp.Omitted = append(resp.Omitted, blobOmitted{BlobIDHex: idHex, ErrorCode: "not_found"})
		case err != nil:
			// Deliberately NOT the 500 the single-blob route returns. A 500 here
			// poisons the whole window, which kills the client's cycle, which
			// means one unreadable file wedges that account's sync permanently.
			// As a per-id omission the client skips the record without adopting a
			// baseline, so the next cycle re-lists it and it self-heals.
			resp.Omitted = append(resp.Omitted, blobOmitted{BlobIDHex: idHex, ErrorCode: "internal"})
		default:
			// Close the response BEFORE the entry that would overrun the byte
			// budget, and stop entirely — the response must describe a clean
			// prefix, so nothing may be appended past the cut. `i > 0` is what
			// lets a lone oversized blob through rather than looping on it
			// forever; the client always gets at least one id accounted for.
			if i > 0 && bytesSoFar+len(ct) > MaxBlobFetchBytes {
				break
			}
			bytesSoFar += len(ct)
			resp.Blobs = append(resp.Blobs, blobEntry{
				BlobIDHex:     idHex,
				CiphertextB64: base64.StdEncoding.EncodeToString(ct),
			})
		}
	}
	writeJSON(w, resp)
}

// MaxVaultMetaSize bounds an uploaded vault.meta (the v0.1 meta is 345 bytes;
// the cap is generous for forward-compat but rejects abuse).
const MaxVaultMetaSize = 64 * 1024

// handleMeta serves the vault.meta blob (MYND-425 enrollment bootstrap):
//
//   - PUT /vault.meta            (authed): an enrolled device uploads its meta.
//
//   - GET /vault.meta?account=<hex> (PRE-AUTH): a new device fetches the meta by
//     account_number_hash to derive root_key before it can SCRAM-authenticate.
//     Necessarily pre-auth: the SCRAM secret is derived FROM root_key, so an
//     authed-only variant is circular.
//
//     The bytes are OPAQUE to this server, which is a claim about what the
//     SERVER learns and not about what a FETCHER gets. This comment used to say
//     "useless without the password", which inverts the property: they are
//     useless only for as long as the password holds. What is served is the
//     complete offline password-cracking target — Argon2id salt, cost
//     parameters, and the wrapped root_key — so anyone holding an account
//     number can obtain it from anywhere, with no device. Since `NTV7` there is
//     one password wrap rather than two plus a person envelope, which is a
//     stronger handle (a random 128-bit vault id rather than 95 derived bits)
//     and not a smaller surface: the password wrap is still the target. That is
//     accepted, and it is recorded where a reader will look for it:
//     docs/threat-model.md §7 (technical) and §5 (plain language).
func (h *Handler) handleMeta(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		// A person session may name the vault it is publishing (`?account=`,
		// myne-md/myne#911 task 7); without the parameter this is exactly the
		// pre-task behaviour, selector-less and byte-identical on the wire.
		//
		// The body is read BEFORE the owner bind runs, because the bind and the
		// frame have to agree: `vaultMetaPublishAccount` records the owner as this
		// person on first write, and `BindOwner` cannot be unwound, so a frame that
		// names a different namespace must be refused before any binding exists.
		// The read is capped at `MaxVaultMetaSize` (64 KiB), so this is not an
		// unbounded body read ahead of authorization.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxVaultMetaSize))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, "too_large")
			return
		}
		var account ids.AccountNumberHash
		var ok bool
		vault, hasSelector, parsed := requestedNamespace(r)
		if hasSelector {
			if !parsed {
				writeErr(w, http.StatusBadRequest, "bad_request")
				return
			}
			// §9.3's namespace field is the 16 bytes at offset 6, and it is exactly
			// what the selector names in every generation (the account hash in the
			// legacy ones, the random vault id in `NTV7`).
			if len(body) < 22 || !bytes.Equal(body[6:22], vault[:]) {
				writeErr(w, http.StatusBadRequest, "bad_request")
				return
			}
			account, ok = h.vaultMetaPublishAccount(w, r, vault)
		} else {
			account, ok = h.vaultMetaWriteAccount(w, r)
		}
		if !ok {
			return
		}
		if h.rl != nil && !h.rl.Allow(account) {
			writeErr(w, http.StatusTooManyRequests, "rate")
			return
		}
		// #9: the third write route the freeze did not cover. A frozen account
		// could still overwrite its own `vault.meta` — the blob every other
		// device bootstraps from — while every note push was refused. The GET
		// arms below stay ungated: freezing must not hold data hostage.
		if h.frozen != nil && h.frozen(account) {
			writeErr(w, http.StatusForbidden, "frozen")
			return
		}
		// The 200 is what the device acts on: it clears the dirty marker and pins
		// this meta as its baseline. Answering ok for a meta the store never
		// wrote does not just lose the upload — the next cycle reads the stale
		// server copy as an authoritative remote change and rolls a password
		// change back. Report the failure so the client retries instead.
		if err := h.store.SetMeta(account, body); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal")
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	case http.MethodGet:
		// Authed fetch (F1 Faz B): an enrolled device polls its meta each sync
		// cycle to pick up a password-side change made on another device. A vault
		// device token asks for its own namespace; a PERSON session names the
		// vault with `?account=` (myne-md/myne#911 task 7), which is why this arm
		// goes through `namespaceSession` and not `session`.
		//
		// The selector must be resolved HERE and not ignored: a person session's
		// own account holds no `vault.meta` (the person namespace carries no
		// blobs), so serving `sess.Account` would answer `404` on every poll for
		// the birth generation, leaving the meta phase's pull half dead and
		// letting a device with a dirty local frame push a stale one over the
		// server's. That is a silent credential rollback, and `server-protocol.md`
		// §3.1a forbids the fallback in words ("never a silent fall back to the
		// caller's own namespace").
		//
		// NOT behind the pre-auth limiter: this is an authenticated read of data
		// the caller is bound to, rate-limited like the other sync routes.
		if _, hasSession := h.session(r); hasSession {
			sess, nsCode := h.namespaceSession(r)
			if nsCode != "" {
				// A refused selector is REFUSED, never retried as a pre-auth
				// fetch: `403` says "not yours" and `400` says "malformed", and
				// neither may become "here is whatever the query names".
				writeErr(w, namespaceRefusalStatus(nsCode), nsCode)
				return
			}
			if h.rl != nil && !h.rl.Allow(sess.Account) {
				writeErr(w, http.StatusTooManyRequests, "rate")
				return
			}
			meta, err := h.store.GetMeta(sess.Account)
			if errors.Is(err, store.ErrNotFound) {
				writeErr(w, http.StatusNotFound, "not_found")
				return
			}
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "internal")
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(meta)
			return
		}
		// Pre-auth (session-less) fetch — gate it with the global pre-auth limiter so
		// it cannot be hammered without bound (no per-account key: the account is an
		// attacker-supplied query value; keying on it would itself be an unbounded map).
		if h.metaLimiter != nil && !h.metaLimiter.Allow() {
			writeErr(w, http.StatusTooManyRequests, "rate")
			return
		}
		// Pre-auth fetch by account_number_hash (the bootstrap).
		account, ok := ids.ParseAccountNumberHash(r.URL.Query().Get("account"))
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad_request")
			return
		}
		meta, err := h.store.GetMeta(account)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not_found")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(meta)

	default:
		writeErr(w, http.StatusMethodNotAllowed, "bad_request")
	}
}
