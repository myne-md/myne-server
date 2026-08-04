// SPDX-License-Identifier: AGPL-3.0

// Package store defines the blind blob store: opaque per-vault ciphertext storage
// with an opaque per-note version counter, an opaque vault-head pointer (CAS), and
// the GC/quota substrate. The store NEVER decrypts, merges, interprets, or reorders
// content (trust boundary TB5); it has no root_key and cannot parse a vault head.
//
// The interface is backend-agnostic: it imposes no transaction requirement, because
// push atomicity is blobs-first-then-head-CAS (ledger SYNC-5). Batch is NOT a
// transaction either — it is a durability-granularity scope that lets a backend
// coalesce the per-vault bookkeeping write a request would otherwise perform once
// per mutation. An FS or SQL backend can implement it later (MYND-421/438) without
// reshaping callers; the in-memory MemStore is the reference implementation for the
// bootstrap skeleton.
package store

import (
	"errors"

	"github.com/myne-md/myne-server/internal/ids"
)

// Version is the opaque, monotonic, sync-internal per-blob counter. It is NOT a
// wall-clock and is never exposed as a user-meaningful timestamp (AS6).
type Version uint64

// ErrNotFound is returned when a blob or head is absent.
var ErrNotFound = errors.New("store: not found")

// ErrReclaimed is returned when a blob's ciphertext body was Layer-2 reclaimed
// (sync-protocol §11.3): the record survives as (uuid, final_version, marker)
// but the bytes are gone. Distinct from ErrNotFound so the API can signal
// "reclaimed, full-reconcile" instead of serving an empty body as if live.
var ErrReclaimed = errors.New("store: blob reclaimed")

// ErrHeadCASMismatch is returned when an AdvanceHead's prev-hash does not match
// the current head pointer (a stale base — a fork the server must not accept).
var ErrHeadCASMismatch = errors.New("store: head CAS mismatch")

// ErrBlobCASMismatch is returned when a PushBlob's base version does not match the
// blob's current version (a stale base — the loser must pull/merge/re-push).
var ErrBlobCASMismatch = errors.New("store: blob CAS mismatch")

// ContentNonceLen is the byte length of the public-header content_nonce the client
// supplies alongside the opaque ciphertext (so the server never parses the blob).
const ContentNonceLen = 24

// SyncMeta is the decryption-free per-blob metadata a pull returns (ledger
// SYNC-6 / sync-protocol §8.1). Nothing here exceeds the already-public header —
// content_nonce is public, version is the opaque counter (AS6), size is the
// quota unit (AS17). AttachmentIDHex (MYND-468) is the full 32-byte
// attachment-id the client supplied at registration, echoed back so a puller
// can resolve the 16-byte sync-id prefix to the byte-transport id without
// waiting on the catalog; it is a value the server already stores for the
// /attachments route — no new exposure. Empty for notes.
type SyncMeta struct {
	BlobID          ids.BlobID
	Version         Version
	ContentNonce    [ContentNonceLen]byte
	Size            int
	AttachmentIDHex string
}

// BlobStore is the blind blob store. Implementations MUST isolate vaults by
// account_number_hash and MUST NOT inspect ciphertext.
type BlobStore interface {
	// PutBlob stores opaque ciphertext for (account, blobID) in that vault's
	// namespace and returns the resulting opaque version. Storing new ciphertext
	// advances the blob's monotonic version counter (see MYND-419 task 4).
	PutBlob(account ids.AccountNumberHash, blobID ids.BlobID, ciphertext []byte) (Version, error)

	// GetBlob returns the stored opaque ciphertext + its version for
	// (account, blobID). Returns ErrNotFound if the blob is absent, or
	// ErrReclaimed if the body was Layer-2 reclaimed (§11.3) — a reclaimed
	// blob must never read as a live empty ciphertext.
	GetBlob(account ids.AccountNumberHash, blobID ids.BlobID) (ciphertext []byte, version Version, err error)

	// BlobVersion returns the current opaque version for (account, blobID) without
	// fetching ciphertext — the CAS base a client compares against on push. Returns
	// ErrNotFound if the blob is absent.
	BlobVersion(account ids.AccountNumberHash, blobID ids.BlobID) (Version, error)

	// GetHead returns the current opaque vault-head record + its head_id
	// (SHA-256 of the record), or ErrNotFound if the vault has no head yet.
	GetHead(account ids.AccountNumberHash) (record []byte, headID [HeadIDLen]byte, err error)

	// SetMeta stores the opaque AEAD vault.meta blob (MYND-425 enrollment
	// bootstrap); GetMeta returns it (ErrNotFound if absent). Served pre-auth by
	// account_number_hash so a new device can derive root_key before SCRAM-auth.
	//
	// It returns its write error like every other durable mutation on this seam,
	// because the PUT's success is what the client acts on: it clears the dirty
	// marker and pins the uploaded meta as its baseline. A swallowed failure
	// therefore costs more than the upload — the next cycle reads the stale
	// server meta as an authoritative remote change and reverts a password
	// change on the very device that made it.
	SetMeta(account ids.AccountNumberHash, meta []byte) error
	GetMeta(account ids.AccountNumberHash) ([]byte, error)

	// AdvanceHead atomically compare-and-swaps the current-head pointer. prevHeadHash
	// MUST equal the current head_id; for the genesis head (no current head) it MUST
	// be the zero hash. A mismatch returns ErrHeadCASMismatch (a stale base — a fork
	// the server must not accept). The server stores the record OPAQUELY and never
	// parses it. Returns the new head_id = SHA-256(record).
	AdvanceHead(account ids.AccountNumberHash, prevHeadHash [HeadIDLen]byte, record []byte) (newHeadID [HeadIDLen]byte, err error)

	// QuotaBytes returns the account's current deduplicated stored-ciphertext byte
	// total (AS17) — one stored blob counted once (by its current size), never once
	// per referencing note. The GC/quota POLICY (ceiling, enforcement, horizon) lives
	// in MYND-422; this is only the substrate counter.
	QuotaBytes(account ids.AccountNumberHash) uint64

	// BlobQuotaBytes returns the bytes (account, blobID) currently contributes to
	// QuotaBytes — 0 for an absent or Layer-2 reclaimed blob. A push REPLACES those
	// bytes rather than adding to them (PushBlob adjusts the counter by the size
	// delta), so this is what a quota gate must subtract to charge a push its actual
	// growth instead of its full size.
	BlobQuotaBytes(account ids.AccountNumberHash, blobID ids.BlobID) uint64

	// SetTombstone records the (note_uuid, final_version, tombstone_marker) triplet
	// for a deleted blob — the server learns only that a uuid reached a final
	// version, never "deleted" meaning (AS6). This is the substrate the MYND-422
	// horizon-GC writes through; it does not itself drop ciphertext (that is L2 policy).
	SetTombstone(account ids.AccountNumberHash, blobID ids.BlobID, finalVersion Version) error

	// Tombstone returns the recorded (final_version, marker) for a blob, if any.
	Tombstone(account ids.AccountNumberHash, blobID ids.BlobID) (finalVersion Version, marked bool)

	// PushBlob stores opaque ciphertext under optimistic compare-and-swap: baseVersion
	// MUST equal the blob's current version (0 for a new blob), else ErrBlobCASMismatch.
	// contentNonce is the client-supplied public-header discriminator (the server never
	// parses the blob). A byte-identical re-push at the correct base is idempotent.
	// A successful version advance clears any tombstone record and the reclaimed
	// mark: a new content version supersedes the deletion (§11.1), so a later GC
	// pass must not reclaim the resurrected body.
	// Returns the resulting version.
	PushBlob(account ids.AccountNumberHash, blobID ids.BlobID, baseVersion Version, contentNonce [ContentNonceLen]byte, ciphertext []byte) (Version, error)

	// ChangedSince returns up to `limit` SyncMeta whose per-vault change-sequence is
	// greater than `cursor`, ordered by that sequence, plus the new cursor (the max
	// sequence in the selected window, or `cursor` if none). It omits Layer-2
	// reclaimed records — a reclaimed uuid is absent from the manifest (§11.3),
	// never a size-0 live meta — but the returned cursor still advances ACROSS
	// them, so a page may legitimately be empty while the cursor moves; a cursor
	// that stalled below the reclaim floor would 410 every later pull. The cursor
	// is opaque, per-device, monotone, wall-clock-free; selection is by the
	// server's own change-sequence, never a timestamp (ledger SYNC-6).
	ChangedSince(account ids.AccountNumberHash, cursor uint64, limit int) (metas []SyncMeta, newCursor uint64)

	// AckCursor records a device's pull cursor position — the ack the MYND-422
	// horizon-GC aggregates into the must-ack set (ledger SYNC-6/SYNC-7).
	AckCursor(account ids.AccountNumberHash, device ids.DeviceID, pos uint64)

	// DeviceCursor returns a device's last acked cursor position (0 if none).
	DeviceCursor(account ids.AccountNumberHash, device ids.DeviceID) uint64

	// TombstoneRecord returns the full tombstone record for GC: final_version, the
	// change-sequence a device must ack past, and whether L2 reclaimed the body.
	TombstoneRecord(account ids.AccountNumberHash, blobID ids.BlobID) (finalVersion Version, changeSeq uint64, reclaimed bool, ok bool)

	// ListTombstones returns every blob id with a tombstone record (GC sweep).
	ListTombstones(account ids.AccountNumberHash) []ids.BlobID

	// ReclaimTombstone is the Layer-2 reclamation: drop the ciphertext body, keep
	// (uuid, final_version, marker). The server never learns "deleted" meaning (AS6).
	ReclaimTombstone(account ids.AccountNumberHash, blobID ids.BlobID) error

	// GCFloor returns the highest change-sequence whose tombstone has been reclaimed.
	// A non-zero pull cursor below this missed reclaimed history → cursor-expired.
	GCFloor(account ids.AccountNumberHash) uint64

	// SetBlobAttachmentID associates the full 32-byte attachment-id (lowercase hex)
	// with a blob record (MYND-468): an attachment's sync-plane record is keyed by
	// the id's first 16 bytes, and the association lets ChangedSince echo the full
	// id back to pullers and lets horizon-GC bridge a reclaimed tombstone record to
	// the attachment body. Opaque to the server (it never derives or parses it).
	SetBlobAttachmentID(account ids.AccountNumberHash, blobID ids.BlobID, attachmentIDHex string) error

	// BlobAttachmentID returns the associated attachment-id hex ("" if the blob is
	// unknown or is a note record).
	BlobAttachmentID(account ids.AccountNumberHash, blobID ids.BlobID) string

	// Batch runs fn as ONE storage batch over a single account's vault. A backend
	// that writes per-vault bookkeeping on every mutation coalesces those writes
	// into one at the end of fn instead of one per mutation — the difference
	// between O(N) and O(N²) for a request carrying N blobs.
	//
	// This is a durability-granularity scope, NOT a transaction: it does not roll
	// back. Every call inside fn keeps its exact semantics (CAS, quota accounting,
	// idempotent replay, error values); what changes is that a crash inside a batch
	// may lose the whole batch's bookkeeping rather than a prefix of it. Bodies are
	// written and durable as before, so what survives such a crash is an orphan
	// body a reopen already ignores — never a partial or corrupt index.
	//
	// The coalesced write happens whether or not fn returns an error: a backend
	// must never leave its in-memory state ahead of disk. Batch returns fn's error
	// if non-nil, else the coalesced write's error. Batches over one account nest;
	// the write happens when the outermost one ends. A backend MUST NOT hold the
	// vault's lock across fn — the calls inside it take that lock themselves.
	Batch(account ids.AccountNumberHash, fn func() error) error

	// DeleteAccount permanently removes an account's entire vault namespace (blobs,
	// meta, head, index, tombstones — and, for the fs backend, the co-located
	// attachments subtree) plus its in-memory index. Irreversible (the operator /
	// self-service deletion path, MYND-506). Idempotent on a missing account.
	DeleteAccount(account ids.AccountNumberHash) error
}

// HeadIDLen is the byte length of a head_id (SHA-256).
const HeadIDLen = 32

// genesisPrevHash is the prevHeadHash a client supplies for the first (genesis)
// head: the all-zero hash, meaning "expect no current head".
var genesisPrevHash [HeadIDLen]byte
