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
	ErrNotFound    = errors.New("attachments: not found")
	ErrTooLarge    = errors.New("attachments: exceeds MYA1 cap")
	ErrBadOffset   = errors.New("attachments: offset beyond current length")
	ErrRangeOOB    = errors.New("attachments: range out of bounds")
	ErrDeclaredLen = errors.New("attachments: declared total length mismatch")
)

type entry struct {
	total    int    // declared total ciphertext length
	data     []byte // assembled bytes [0:len(data)] uploaded so far
	complete bool
}

// Store is the in-memory per-vault attachment store (reference impl; a production
// backend implements the same surface later, MYND-438).
type Store struct {
	mu     sync.RWMutex
	vaults map[ids.AccountNumberHash]map[AttachmentID]*entry
}

// NewStore returns an empty attachment store.
func NewStore() *Store {
	return &Store{vaults: make(map[ids.AccountNumberHash]map[AttachmentID]*entry)}
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
func (s *Store) Has(a ids.AccountNumberHash, id AttachmentID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.vaults[a][id]
	return e != nil && e.complete
}

// UploadedLen returns how many bytes have been uploaded for an in-progress (or
// complete) attachment, and whether it is known at all (for resume).
func (s *Store) UploadedLen(a ids.AccountNumberHash, id AttachmentID) (n int, known bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.vaults[a][id]
	if e == nil {
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
	if e == nil {
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
	if e == nil || !e.complete {
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
	delete(s.vault(a), id)
}
