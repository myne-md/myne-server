// SPDX-License-Identifier: AGPL-3.0

// Package attachments stores opaque attachment ciphertext (MYA1 blobs) per vault
// and serves it over resumable byte-range transport (MYND-423). The AEAD is NEVER
// chunked: a MYA1 blob is a single 64 MiB atomic CTX-tag unit; ranges carry only
// opaque ciphertext bytes and the whole-blob tag is verified CLIENT-side after
// reassembly (an interrupted/tampered transfer fails the single tag → re-fetch).
// This structurally eliminates the CCS-2024 unauthenticated-chunking class. Dedup
// is per-vault by the client-supplied keyed content-id (attachment-id); cross-vault
// dedup is structurally impossible (the id is root_key-derived).
package attachments

import (
	"errors"
	"sync"

	"github.com/myne-md/myne-server/internal/ids"
)

// AttachmentIDLen is the byte length of an attachment-id (HMAC-SHA-256).
const AttachmentIDLen = 32

// MaxAttachmentSize is the MYA1 cap (64 MiB) + the 32-byte CTX tag.
const MaxAttachmentSize = 64*1024*1024 + 32

// AttachmentID is the per-vault content-id (keyed HMAC of the plaintext, client-
// derived). The server treats it as an opaque key.
type AttachmentID [AttachmentIDLen]byte

// Errors.
var (
	ErrNotFound           = errors.New("attachments: not found")
	ErrTooLarge           = errors.New("attachments: exceeds MYA1 cap")
	ErrBadOffset          = errors.New("attachments: offset beyond current length")
	ErrRangeOOB           = errors.New("attachments: range out of bounds")
	ErrDeclaredLen        = errors.New("attachments: declared total length mismatch")
	ErrTooManyAttachments = errors.New("attachments: too many attachment ids for this vault")
)

// Backend is the attachment-store surface the transport handler + the GC bridge
// consume (MYND-468). Two implementations: the in-memory [Store] (dev/E2E
// reference) and the durable [FSStore] (production fs backend). Deleted-is-absent
// discipline: a MarkDeleted id reads as unknown (HEAD/GET 404, non-distinguishing
// from never-uploaded, `sync-protocol.md` §11.4) until Reclaim physically drops it.
type Backend interface {
	// Has reports whether a COMPLETE, non-deleted attachment exists (dedup probe).
	Has(a ids.AccountNumberHash, id AttachmentID) bool
	// UploadedLen returns the uploaded byte count + whether the id is known
	// (deleted ids are NOT known — deleted-is-absent).
	UploadedLen(a ids.AccountNumberHash, id AttachmentID) (n int, known bool)
	// WriteAt appends a strictly-sequential chunk (see Store.WriteAt). Writing to
	// a deleted id restarts it as a fresh upload (the §11.4 re-add).
	WriteAt(a ids.AccountNumberHash, id AttachmentID, offset, total int, chunk []byte) error
	// ReadRange serves bytes of a complete, non-deleted attachment.
	ReadRange(a ids.AccountNumberHash, id AttachmentID, start, length int) (chunk []byte, total int, err error)
	// AccountBytes is the account's live attachment byte total (unified AS17 input).
	AccountBytes(a ids.AccountNumberHash) uint64
	// MarkDeleted hides the body (absent to Has/UploadedLen/ReadRange) without
	// dropping it — the state between the client's §11.4 tombstone push and the
	// horizon-GC reclaim (ExtendedRetention keeps bodies in exactly this state).
	MarkDeleted(a ids.AccountNumberHash, id AttachmentID)
	// Reclaim physically drops the body + partial state, frees the id's slot under
	// the per-vault ceiling, and returns the bytes released from the quota total.
	// ok=false when the id is unknown.
	Reclaim(a ids.AccountNumberHash, id AttachmentID) (bytesFreed uint64, ok bool)
	// DeleteAccount drops the account's in-memory attachment index (MYND-506). For
	// the fs backend the bodies themselves live under the blob store's account dir and
	// are removed by store.DeleteAccount; this only clears the index.
	DeleteAccount(a ids.AccountNumberHash)
}

type entry struct {
	total    int    // declared total ciphertext length
	data     []byte // assembled bytes [0:len(data)] uploaded so far
	complete bool
	deleted  bool // §11.4 tombstoned — reads as absent until reclaimed
}

// Store is the in-memory per-vault attachment store (reference impl; the
// production fs backend is [FSStore], MYND-468).
type Store struct {
	mu sync.RWMutex
	// accountBytes is the live per-account total (completed + in-progress uploads) so
	// attachment storage folds into the same per-account AS17 ceiling as blob storage.
	accountBytes   map[ids.AccountNumberHash]uint64
	maxIDsPerVault int // 0 = unlimited; caps distinct attachment ids per vault (OOM bound)
	vaults         map[ids.AccountNumberHash]map[AttachmentID]*entry
}

// DeleteAccount drops the account's in-memory attachment index + byte total (MYND-506).
func (s *Store) DeleteAccount(a ids.AccountNumberHash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.vaults, a)
	delete(s.accountBytes, a)
}

// NewStore returns an empty attachment store (unlimited id count until WithMaxIDs).
func NewStore() *Store {
	return &Store{
		vaults:       make(map[ids.AccountNumberHash]map[AttachmentID]*entry),
		accountBytes: make(map[ids.AccountNumberHash]uint64),
	}
}

// WithMaxIDs caps the number of distinct attachment ids a single vault may hold
// (0 = unlimited). The cap counts BOTH completed and in-progress ids — the real
// OOM vector is thousands of half-finished uploads, each holding up to 64 MiB.
func (s *Store) WithMaxIDs(n int) *Store {
	s.maxIDsPerVault = n
	return s
}

// AccountBytes returns the account's live attachment byte total.
func (s *Store) AccountBytes(a ids.AccountNumberHash) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accountBytes[a]
}

func (s *Store) vault(a ids.AccountNumberHash) map[AttachmentID]*entry {
	v := s.vaults[a]
	if v == nil {
		v = make(map[AttachmentID]*entry)
		s.vaults[a] = v
	}
	return v
}

// Has reports whether a complete attachment with this id already exists in the
// vault (the dedup check — a present id means the client can skip the upload).
// A deleted id reads as absent (§11.4).
func (s *Store) Has(a ids.AccountNumberHash, id AttachmentID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.vaults[a][id]
	return e != nil && e.complete && !e.deleted
}

// UploadedLen returns how many bytes have been uploaded for an in-progress (or
// complete) attachment, and whether it is known at all (for resume). A deleted
// id reads as unknown (§11.4 deleted-is-absent).
func (s *Store) UploadedLen(a ids.AccountNumberHash, id AttachmentID) (n int, known bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.vaults[a][id]
	if e == nil || e.deleted {
		return 0, false
	}
	return len(e.data), true
}

// WriteAt appends a chunk at the given offset (resumable upload). offset must equal
// the current uploaded length (strictly sequential resume). total is the declared
// full ciphertext length (must be consistent across chunks). When the assembled
// length reaches total, the attachment is marked complete.
func (s *Store) WriteAt(a ids.AccountNumberHash, id AttachmentID, offset, total int, chunk []byte) error {
	if total > MaxAttachmentSize {
		return ErrTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vault(a)
	e := v[id]
	if e != nil && e.deleted {
		// A PUT to a deleted id is the §11.4 re-add: restart as a fresh upload
		// (the retained body is stale — content-addressing makes the plaintext
		// identical, but the ciphertext is a fresh encryption).
		if n := uint64(len(e.data)); s.accountBytes[a] >= n {
			s.accountBytes[a] -= n
		} else {
			s.accountBytes[a] = 0
		}
		e = nil
		delete(v, id)
	}
	if e == nil {
		// A new id: refuse once the per-vault id cap is hit (bounds the number of
		// concurrent half-finished uploads, the real memory-exhaustion vector).
		if s.maxIDsPerVault > 0 && len(v) >= s.maxIDsPerVault {
			return ErrTooManyAttachments
		}
		e = &entry{total: total}
		v[id] = e
	}
	if e.total != total {
		return ErrDeclaredLen
	}
	if offset != len(e.data) {
		return ErrBadOffset
	}
	if len(e.data)+len(chunk) > total {
		return ErrRangeOOB
	}
	e.data = append(e.data, chunk...)
	s.accountBytes[a] += uint64(len(chunk))
	if len(e.data) == total {
		e.complete = true
	}
	return nil
}

// ReadRange returns ciphertext bytes [start, start+length) of a complete
// attachment, plus the total length. The server serves opaque bytes; the client
// verifies the whole-blob tag after reassembly.
func (s *Store) ReadRange(a ids.AccountNumberHash, id AttachmentID, start, length int) (chunk []byte, total int, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.vaults[a][id]
	if e == nil || !e.complete || e.deleted {
		return nil, 0, ErrNotFound
	}
	if start < 0 || start > len(e.data) {
		return nil, 0, ErrRangeOOB
	}
	end := start + length
	if length <= 0 || end > len(e.data) {
		end = len(e.data)
	}
	out := make([]byte, end-start)
	copy(out, e.data[start:end])
	return out, len(e.data), nil
}

// Delete removes an attachment (the user-triggered sweep's effect; the deletion
// propagates as a §11 tombstone via gc-quota, not a bare server delete).
func (s *Store) Delete(a ids.AccountNumberHash, id AttachmentID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vault(a)
	if e := v[id]; e != nil {
		if n := uint64(len(e.data)); s.accountBytes[a] >= n {
			s.accountBytes[a] -= n
		} else {
			s.accountBytes[a] = 0
		}
	}
	delete(v, id)
}

// MarkDeleted hides the body without dropping it (§11.4: the state between the
// client's tombstone push and the horizon-GC reclaim). Idempotent; unknown id
// is a no-op. Bytes keep counting against the quota until Reclaim — symmetric
// with a tombstoned-but-unreclaimed note blob.
func (s *Store) MarkDeleted(a ids.AccountNumberHash, id AttachmentID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.vaults[a][id]; e != nil {
		e.deleted = true
	}
}

// Reclaim physically drops the body + partial state and frees the id's slot.
// Returns the bytes released from the account total; ok=false for an unknown id.
func (s *Store) Reclaim(a ids.AccountNumberHash, id AttachmentID) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vault(a)
	e := v[id]
	if e == nil {
		return 0, false
	}
	freed := uint64(len(e.data))
	if s.accountBytes[a] >= freed {
		s.accountBytes[a] -= freed
	} else {
		s.accountBytes[a] = 0
	}
	delete(v, id)
	return freed, true
}

// compile-time assertion that the in-memory Store implements Backend.
var _ Backend = (*Store)(nil)
