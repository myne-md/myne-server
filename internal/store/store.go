// SPDX-License-Identifier: AGPL-3.0

// Package store defines the blind blob store: opaque per-vault ciphertext storage
// with an opaque per-note version counter, an opaque vault-head pointer (CAS), and
// the GC/quota substrate. The store NEVER decrypts, merges, interprets, or reorders
// content (trust boundary TB5); it has no root_key and cannot parse a vault head.
//
// The interface is backend-agnostic: it imposes no transaction requirement, because
// push atomicity is blobs-first-then-head-CAS (ledger SYNC-5). An FS or SQL backend
// can implement it later (MYND-421/438) without reshaping callers; the in-memory
// MemStore is the reference implementation for the bootstrap skeleton.
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

// ErrHeadCASMismatch is returned when an AdvanceHead's prev-hash does not match
// the current head pointer (a stale base — a fork the server must not accept).
var ErrHeadCASMismatch = errors.New("store: head CAS mismatch")

// ErrBlobCASMismatch is returned when a PushBlob's base version does not match the
// blob's current version (a stale base — the loser must pull/merge/re-push).
var ErrBlobCASMismatch = errors.New("store: blob CAS mismatch")

// ContentNonceLen is the byte length of the public-header content_nonce the client
// supplies alongside the opaque ciphertext (so the server never parses the blob).
const ContentNonceLen = 24

// SyncMeta is the decryption-free per-blob metadata a pull returns: exactly four
// fields (ledger SYNC-6 / sync-protocol §8.1). Nothing here exceeds the already-
// public header — content_nonce is public, version is the opaque counter (AS6),
// size is the quota unit (AS17).
type SyncMeta struct {
	BlobID       ids.BlobID
	Version      Version
	ContentNonce [ContentNonceLen]byte
	Size         int
}

// BlobStore is the blind blob store. Implementations MUST isolate vaults by
// account_number_hash and MUST NOT inspect ciphertext.
type BlobStore interface {
	// PutBlob stores opaque ciphertext for (account, blobID) in that vault's
	// namespace and returns the resulting opaque version. Storing new ciphertext
	// advances the blob's monotonic version counter (see MYND-419 task 4).
	PutBlob(account ids.AccountNumberHash, blobID ids.BlobID, ciphertext []byte) (Version, error)

	// GetBlob returns the stored opaque ciphertext + its version for
	// (account, blobID), or ErrNotFound.
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
	SetMeta(account ids.AccountNumberHash, meta []byte)
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
	// Returns the resulting version.
	PushBlob(account ids.AccountNumberHash, blobID ids.BlobID, baseVersion Version, contentNonce [ContentNonceLen]byte, ciphertext []byte) (Version, error)

	// ChangedSince returns up to `limit` SyncMeta whose per-vault change-sequence is
	// greater than `cursor`, ordered by that sequence, plus the new cursor (the max
	// sequence returned, or `cursor` if none). The cursor is opaque, per-device,
	// monotone, wall-clock-free; selection is by the server's own change-sequence,
	// never a timestamp (ledger SYNC-6).
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
}

// HeadIDLen is the byte length of a head_id (SHA-256).
const HeadIDLen = 32

// genesisPrevHash is the prevHeadHash a client supplies for the first (genesis)
// head: the all-zero hash, meaning "expect no current head".
var genesisPrevHash [HeadIDLen]byte
