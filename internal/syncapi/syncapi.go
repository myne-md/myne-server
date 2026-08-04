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

// RateLimiter gates requests per account (nil = disabled).
type RateLimiter interface {
	Allow(account ids.AccountNumberHash) bool
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
	// authenticated one; nil = the endpoint reports unavailable.
	accountStatus func(account ids.AccountNumberHash) any
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
// invoked with the AUTHENTICATED account (never a URL/query value).
func (h *Handler) WithAccountStatus(fn func(account ids.AccountNumberHash) any) *Handler {
	h.accountStatus = fn
	return h
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
	mux.HandleFunc("/vault.meta", h.handleMeta)
	mux.HandleFunc("/account/status", h.handleAccountStatus)
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
	writeJSON(w, h.accountStatus(sess.Account))
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
	tok, err := hex.DecodeString(strings.TrimPrefix(authz, pfx))
	if err != nil {
		return auth.Session{}, "unauthenticated"
	}
	sess, err := h.auth.AuthenticateSession(ids.DeviceToken(tok))
	if err != nil {
		return auth.Session{}, auth.FailureCode(err)
	}
	return sess, ""
}

// session extracts + validates the bearer token, returning the bound session.
func (h *Handler) session(r *http.Request) (auth.Session, bool) {
	authz := r.Header.Get("Authorization")
	const pfx = "Bearer "
	if !strings.HasPrefix(authz, pfx) {
		return auth.Session{}, false
	}
	tok, err := hex.DecodeString(strings.TrimPrefix(authz, pfx))
	if err != nil {
		return auth.Session{}, false
	}
	sess, err := h.auth.AuthenticateSession(ids.DeviceToken(tok))
	if err != nil {
		return auth.Session{}, false
	}
	return sess, true
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
	if r.Method != http.MethodPost {
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

// MaxVaultMetaSize bounds an uploaded vault.meta (the v0.1 meta is 345 bytes;
// the cap is generous for forward-compat but rejects abuse).
const MaxVaultMetaSize = 64 * 1024

// handleMeta serves the vault.meta blob (MYND-425 enrollment bootstrap):
//   - PUT /vault.meta            (authed): an enrolled device uploads its meta.
//   - GET /vault.meta?account=<hex> (PRE-AUTH): a new device fetches the meta by
//     account_number_hash to derive root_key before it can SCRAM-authenticate.
//     The bytes are AEAD-protected (useless without the password), so serving by
//     account# is the accepted A4-equivalent exposure (same as 24-word recovery).
func (h *Handler) handleMeta(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		sess, authCode := h.sessionWithCode(r)
		if authCode != "" {
			writeErr(w, http.StatusUnauthorized, authCode)
			return
		}
		if h.rl != nil && !h.rl.Allow(sess.Account) {
			writeErr(w, http.StatusTooManyRequests, "rate")
			return
		}
		// #9: the third write route the freeze did not cover. A frozen account
		// could still overwrite its own `vault.meta` — the blob every other
		// device bootstraps from — while every note push was refused. The GET
		// arms below stay ungated: freezing must not hold data hostage.
		if h.frozen != nil && h.frozen(sess.Account) {
			writeErr(w, http.StatusForbidden, "frozen")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxVaultMetaSize))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, "too_large")
			return
		}
		// The 200 is what the device acts on: it clears the dirty marker and pins
		// this meta as its baseline. Answering ok for a meta the store never
		// wrote does not just lose the upload — the next cycle reads the stale
		// server copy as an authoritative remote change and rolls a password
		// change back. Report the failure so the client retries instead.
		if err := h.store.SetMeta(sess.Account, body); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal")
			return
		}
		writeJSON(w, map[string]bool{"ok": true})

	case http.MethodGet:
		// Authed fetch (F1 Faz B): an enrolled device polls its OWN meta each sync
		// cycle to pick up a password-side change made on another device. A valid
		// session serves the session's account directly — no ?account= query, and
		// NOT behind the pre-auth limiter (it is the enrolled device's own data,
		// rate-limited like the other sync routes). Falls through to the pre-auth
		// bootstrap path only when there is no session.
		if sess, ok := h.session(r); ok {
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
