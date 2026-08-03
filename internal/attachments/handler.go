// SPDX-License-Identifier: AGPL-3.0

package attachments

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
)

// RateLimiter gates per-account requests (nil = disabled) — the same seam the sync
// path uses, so an attachment flood is bounded exactly like a push flood.
type RateLimiter interface {
	Allow(account ids.AccountNumberHash) bool
}

// AttachQuota reports whether currentBytes+addBytes would cross the account's
// effective per-account ceiling (nil = disabled). It is store-agnostic so attachment
// bytes fold into the SAME AS17 total as blob bytes, and the per-account quota
// override (MYND-506) applies here too (see gcquota.QuotaGuard.WouldExceedTotalForAccount).
type AttachQuota interface {
	WouldExceedTotalForAccount(account ids.AccountNumberHash, currentBytes, addBytes uint64) bool
}

// Handler serves the resumable attachment transport. Every route is session-bound
// via the MYND-420 per-device token.
type Handler struct {
	store Backend
	auth  *auth.TokenStore
	rl    RateLimiter
	qg    AttachQuota
	// used reports the account's byte total held OUTSIDE this store (the blob store's
	// QuotaBytes), so the quota check gates on the unified per-account AS17 figure.
	used func(ids.AccountNumberHash) uint64
	// onStored is the aggregate-only metrics hook (SYNC-24): called with the total
	// byte length when an upload COMPLETES. No account/IP ever crosses it.
	onStored func(int)
	// frozen reports whether an account is operator-frozen (MYND-506, #9).
	//
	// The freeze was installed on `/sync/push` only, and the client uploads
	// attachments BEFORE it pushes — so a frozen account kept writing attachment
	// bytes that only the push would have refused, and those bytes are the ones
	// GC cannot reclaim (no head references them). PULL is never gated, here as
	// on the sync route: freezing must not hold data hostage.
	// nil = no freeze wired.
	frozen func(account ids.AccountNumberHash) bool
}

// WithFrozenCheck gates the WRITE route on the operator freeze (#9). Reads are
// never gated — the "frozen is minimal" invariant.
func (h *Handler) WithFrozenCheck(fn func(account ids.AccountNumberHash) bool) *Handler {
	h.frozen = fn
	return h
}

// New returns an attachment Handler over any Backend (in-memory or fs).
func New(s Backend, ts *auth.TokenStore) *Handler {
	return &Handler{store: s, auth: ts}
}

// WithMetrics attaches the aggregate-only completion hook (MYND-468; SYNC-24
// discipline — feeds myne_attachments_stored_total / myne_attachment_bytes_stored_total).
func (h *Handler) WithMetrics(onStored func(int)) *Handler {
	h.onStored = onStored
	return h
}

// WithPolicy attaches the per-account rate-limiter + the unified quota guard. `used`
// supplies the account's byte total from the blob store so attachment bytes are
// counted against the same AS17 ceiling (never a separate, bypassable budget). Any
// of rl/qg/used may be nil (that gate disabled).
func (h *Handler) WithPolicy(rl RateLimiter, qg AttachQuota, used func(ids.AccountNumberHash) uint64) *Handler {
	h.rl = rl
	h.qg = qg
	h.used = used
	return h
}

// Register wires the attachment routes (Go 1.22 method+path patterns).
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("HEAD /attachments/{id}", h.handleHead)
	mux.HandleFunc("GET /attachments/{id}", h.handleGet)
	mux.HandleFunc("PUT /attachments/{id}", h.handlePut)
}

// session extracts + validates the bearer token, returning the bound session and
// — when it fails — the wire `error_code` the 401 must carry.
//
// The code is returned rather than folded into a bool because
// `server-protocol.md` §3.1 makes `device_revoked` a MUST on **every** authed
// route, and these three are authed. A client whose sync routes learn it was
// revoked while its attachment routes keep saying `unauthenticated` would see
// the terminal signal only on whichever request happened to land first — which
// is a race, not a policy.
func (h *Handler) session(r *http.Request) (auth.Session, string) {
	const pfx = "Bearer "
	authz := r.Header.Get("Authorization")
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

// writeAuthErr answers an authentication failure on the attachment routes.
//
// These routes otherwise answer with a bare status and no body — they move
// opaque ciphertext, and there is nothing to say about a bad range or a missing
// id that the status does not already say. The 401 is the exception, because the
// code IS the message: it is the only way the client can tell a stale session
// from a removal it must honour.
func writeAuthErr(w http.ResponseWriter, code string) {
	// The code goes in a HEADER as well as the body (#7).
	//
	// A HEAD response has no body — Go's net/http discards what a handler
	// writes, and the client's codec does not read one either. So on the resume
	// probe, the one route where `device_revoked` decides whether this browser
	// erases its local copy, the signal was written into a place neither side
	// could ever see. The body stays for the GET/PUT routes, which do carry one;
	// the header is what makes the HEAD route able to say the same thing.
	w.Header().Set("X-Error-Code", code)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = fmt.Fprintf(w, `{"error_code":%q}`, code)
}

// ParseID decodes a lowercase-hex 32-byte attachment-id. Exported for the
// composition layer (the GC reclaim bridge re-parses the id it stored as hex).
func ParseID(s string) (AttachmentID, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != AttachmentIDLen {
		return AttachmentID{}, false
	}
	var id AttachmentID
	copy(id[:], b)
	return id, true
}

// handleHead reports the current uploaded length + completeness — the resume +
// dedup probe. 200 with X-Uploaded-Length / X-Complete if known; 404 if unknown.
func (h *Handler) handleHead(w http.ResponseWriter, r *http.Request) {
	sess, authCode := h.session(r)
	if authCode != "" {
		writeAuthErr(w, authCode)
		return
	}
	if h.rl != nil && !h.rl.Allow(sess.Account) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	id, ok := ParseID(r.PathValue("id"))
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	n, known := h.store.UploadedLen(sess.Account, id)
	if !known {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("X-Uploaded-Length", strconv.Itoa(n))
	if h.store.Has(sess.Account, id) {
		w.Header().Set("X-Complete", "1")
	}
	w.WriteHeader(http.StatusOK)
}

// handlePut resumably uploads a chunk at ?offset=N (must equal the current uploaded
// length) declaring ?total=M. Opaque ciphertext only; the AEAD is never chunked —
// these are transport ranges over one atomic blob.
func (h *Handler) handlePut(w http.ResponseWriter, r *http.Request) {
	sess, authCode := h.session(r)
	if authCode != "" {
		writeAuthErr(w, authCode)
		return
	}
	// #9: a frozen account may not WRITE here either.
	//
	// The freeze gated `/sync/push` and nothing else, and the client uploads
	// attachments before it pushes — so a frozen account stored attachment bytes
	// indefinitely, and they are the bytes GC cannot reclaim: no head references
	// them, so the horizon sweep never sees them as collectable. Same 403
	// `frozen` code the sync route answers with, so the client's existing
	// mapping covers it.
	if h.frozen != nil && h.frozen(sess.Account) {
		w.Header().Set("X-Error-Code", "frozen")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error_code":"frozen"}`)
		return
	}
	if h.rl != nil && !h.rl.Allow(sess.Account) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	id, ok := ParseID(r.PathValue("id"))
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	offset, err1 := strconv.Atoi(r.URL.Query().Get("offset"))
	total, err2 := strconv.Atoi(r.URL.Query().Get("total"))
	if err1 != nil || err2 != nil || offset < 0 || total < 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Reserve the declared total against the UNIFIED per-account ceiling when a new
	// upload starts (offset==0): attachment bytes + blob bytes share one AS17 ceiling,
	// so this path cannot be used to store past the quota the sync path enforces.
	if h.qg != nil && offset == 0 {
		var current uint64
		if h.used != nil {
			current = h.used(sess.Account)
		}
		current += h.store.AccountBytes(sess.Account)
		if h.qg.WouldExceedTotalForAccount(sess.Account, current, uint64(total)) {
			w.WriteHeader(http.StatusInsufficientStorage)
			return
		}
	}
	chunk, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxAttachmentSize+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	werr := h.store.WriteAt(sess.Account, id, offset, total, chunk)
	switch werr {
	case nil:
		// ok
	case ErrTooLarge:
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	case ErrTooManyAttachments:
		w.WriteHeader(http.StatusInsufficientStorage) // per-vault id cap reached
		return
	case ErrBadOffset, ErrRangeOOB, ErrDeclaredLen:
		w.WriteHeader(http.StatusConflict) // resume-offset conflict — client re-probes via HEAD
		return
	default:
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	n, _ := h.store.UploadedLen(sess.Account, id)
	if h.onStored != nil && n == total && offset+len(chunk) == total {
		// The upload just completed with this chunk — one aggregate observation.
		h.onStored(total)
	}
	w.Header().Set("X-Uploaded-Length", strconv.Itoa(n))
	w.WriteHeader(http.StatusOK)
}

// handleGet serves the attachment, honoring a single Range: bytes=start-end header
// (206) or the whole blob (200). Bytes are opaque ciphertext; the client verifies
// the whole-blob tag after reassembly and re-fetches on failure.
func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	sess, authCode := h.session(r)
	if authCode != "" {
		writeAuthErr(w, authCode)
		return
	}
	if h.rl != nil && !h.rl.Allow(sess.Account) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	id, ok := ParseID(r.PathValue("id"))
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	start, length, partial, ok := parseRange(r.Header.Get("Range"))
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	chunk, total, err := h.store.ReadRange(sess.Account, id, start, length)
	if err == ErrNotFound {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	if partial {
		end := start + len(chunk) - 1
		if len(chunk) == 0 {
			end = start
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, total))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_, _ = w.Write(chunk)
}

// parseRange parses a single "bytes=start-end" range. Empty header = whole blob.
func parseRange(h string) (start, length int, partial bool, ok bool) {
	if h == "" {
		return 0, 0, false, true
	}
	if !strings.HasPrefix(h, "bytes=") {
		return 0, 0, false, false
	}
	spec := strings.TrimPrefix(h, "bytes=")
	if strings.Contains(spec, ",") {
		return 0, 0, false, false // multi-range unsupported
	}
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return 0, 0, false, false
	}
	s, err := strconv.Atoi(spec[:dash])
	if err != nil || s < 0 {
		return 0, 0, false, false
	}
	if spec[dash+1:] == "" {
		return s, 0, true, true // open-ended: start- → to end
	}
	e, err := strconv.Atoi(spec[dash+1:])
	if err != nil || e < s {
		return 0, 0, false, false
	}
	return s, e - s + 1, true, true
}
