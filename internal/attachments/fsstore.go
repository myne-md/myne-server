// SPDX-License-Identifier: AGPL-3.0

package attachments

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// FSStore is the durable filesystem Backend (MYND-468; completes the MYND-423
// transport whose reference store is in-memory). It shares the blob FSStore's
// per-vault volume so one snapshot captures blobs + attachments + auth together:
//
//	<root>/<account_hex>/attachments/<id_hex>          complete body
//	<root>/<account_hex>/attachments/<id_hex>.partial  in-progress upload
//	<root>/<account_hex>/attachments-index.json        per-account metadata index
//
// Resume vs atomic-write: chunks APPEND to the .partial file with no per-chunk
// fsync — an ACK'd-but-lost tail self-heals (the HEAD probe reports the real
// file size and the client resumes from it) and content integrity is the
// client's whole-blob CTX tag (`server-protocol.md` §3.2), so per-chunk
// durability buys nothing. Completion is fsync + rename to the final name (the
// commit point) + dir-fsync. The index is written via store.AtomicWrite on
// upload-start / completion / delete / reclaim — never per chunk. Load() trusts
// FILE SIZES over the index on drift, finalizes a crashed partial==total file,
// drops index entries whose files vanished, and rebuilds the per-account quota
// counter from disk — restart-proof unified AS17 accounting.
type FSStore struct {
	mu             sync.RWMutex
	root           string
	maxIDsPerVault int
	vaults         map[ids.AccountNumberHash]map[AttachmentID]*fsEntry
	accountBytes   map[ids.AccountNumberHash]uint64
}

type fsEntry struct {
	total    int
	uploaded int
	complete bool
	deleted  bool
}

const attachmentsIndexFile = "attachments-index.json"

type fsIndexEntry struct {
	Total    int  `json:"total"`
	Complete bool `json:"complete"`
	Deleted  bool `json:"deleted,omitempty"`
}

// NewFSStore opens (creating if absent) the attachment backend rooted at the
// SAME dir as the blob FSStore and reconciles every account's index against
// the files actually on disk.
func NewFSStore(root string) (*FSStore, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	s := &FSStore{
		root:         root,
		vaults:       make(map[ids.AccountNumberHash]map[AttachmentID]*fsEntry),
		accountBytes: make(map[ids.AccountNumberHash]uint64),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// WithMaxIDs caps distinct attachment ids per vault (0 = unlimited); counts
// completed + in-progress + deleted-awaiting-reclaim (each holds disk).
func (s *FSStore) WithMaxIDs(n int) *FSStore {
	s.maxIDsPerVault = n
	return s
}

func (s *FSStore) accountDir(a ids.AccountNumberHash) string {
	return filepath.Join(s.root, hex.EncodeToString(a[:]))
}
func (s *FSStore) attachmentsDir(a ids.AccountNumberHash) string {
	return filepath.Join(s.accountDir(a), "attachments")
}
func (s *FSStore) finalPath(a ids.AccountNumberHash, id AttachmentID) string {
	return filepath.Join(s.attachmentsDir(a), hex.EncodeToString(id[:]))
}
func (s *FSStore) partialPath(a ids.AccountNumberHash, id AttachmentID) string {
	return s.finalPath(a, id) + ".partial"
}
func (s *FSStore) indexPath(a ids.AccountNumberHash) string {
	return filepath.Join(s.accountDir(a), attachmentsIndexFile)
}

func (s *FSStore) load() error {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return err
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		acctBytes, err := hex.DecodeString(ent.Name())
		if err != nil || len(acctBytes) != ids.AccountNumberHashLen {
			continue // not a vault dir
		}
		var acct ids.AccountNumberHash
		copy(acct[:], acctBytes)

		raw, err := os.ReadFile(s.indexPath(acct))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		var idx map[string]fsIndexEntry
		if err := json.Unmarshal(raw, &idx); err != nil {
			return err
		}
		v := make(map[AttachmentID]*fsEntry, len(idx))
		var dirty bool
		for idHex, ie := range idx {
			id, ok := ParseID(idHex)
			if !ok {
				dirty = true
				continue
			}
			e := &fsEntry{total: ie.Total, deleted: ie.Deleted}
			// Files are the authority over the index (a crash may have lost
			// the index write that followed an append or a rename).
			if fi, err := os.Stat(s.finalPath(acct, id)); err == nil {
				e.uploaded = int(fi.Size())
				e.total = e.uploaded
				e.complete = true
			} else if fi, err := os.Stat(s.partialPath(acct, id)); err == nil {
				e.uploaded = int(fi.Size())
				if e.total > 0 && e.uploaded >= e.total {
					// Crash between the final append and the rename — finalize.
					if err := s.finalize(acct, id); err != nil {
						return err
					}
					e.uploaded = e.total
					e.complete = true
				}
				dirty = true // partial state always re-persists (sizes may drift)
			} else {
				// Index entry with no file at all → drop it (self-heal). A
				// deleted entry legitimately keeps files until reclaim, so a
				// fileless deleted entry is likewise stale.
				dirty = true
				continue
			}
			if ie.Complete != e.complete {
				dirty = true
			}
			v[id] = e
			s.accountBytes[acct] += uint64(e.uploaded)
		}
		s.vaults[acct] = v
		if dirty {
			if err := s.persist(acct); err != nil {
				return err
			}
		}
	}
	return nil
}

// persist writes the account's index atomically. Callers hold mu.
func (s *FSStore) persist(a ids.AccountNumberHash) error {
	v := s.vaults[a]
	idx := make(map[string]fsIndexEntry, len(v))
	for id, e := range v {
		idx[hex.EncodeToString(id[:])] = fsIndexEntry{Total: e.total, Complete: e.complete, Deleted: e.deleted}
	}
	raw, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	return store.AtomicWrite(s.indexPath(a), raw)
}

// finalize commits a full partial file: fsync + rename to the final name +
// dir-fsync (the old-or-new-never-partial commit point). Callers hold mu.
func (s *FSStore) finalize(a ids.AccountNumberHash, id AttachmentID) error {
	partial := s.partialPath(a, id)
	f, err := os.OpenFile(partial, os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(partial, s.finalPath(a, id)); err != nil {
		return err
	}
	if d, err := os.Open(s.attachmentsDir(a)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (s *FSStore) vault(a ids.AccountNumberHash) map[AttachmentID]*fsEntry {
	v := s.vaults[a]
	if v == nil {
		v = make(map[AttachmentID]*fsEntry)
		s.vaults[a] = v
	}
	return v
}

// Has reports a complete, non-deleted attachment (dedup probe).
func (s *FSStore) Has(a ids.AccountNumberHash, id AttachmentID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.vaults[a][id]
	return e != nil && e.complete && !e.deleted
}

// UploadedLen returns the uploaded byte count (+known); deleted-is-absent.
func (s *FSStore) UploadedLen(a ids.AccountNumberHash, id AttachmentID) (int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.vaults[a][id]
	if e == nil || e.deleted {
		return 0, false
	}
	return e.uploaded, true
}

// WriteAt appends a strictly-sequential chunk to the partial file; when the
// assembled length reaches total, the upload is committed (fsync + rename).
func (s *FSStore) WriteAt(a ids.AccountNumberHash, id AttachmentID, offset, total int, chunk []byte) error {
	if total > MaxAttachmentSize {
		return ErrTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vault(a)
	e := v[id]
	if e != nil && e.deleted {
		// §11.4 re-add: restart as a fresh upload (drop the stale retained body).
		if _, ok := s.reclaimLocked(a, id); !ok {
			return ErrBadOffset
		}
		e = nil
	}
	if e == nil {
		if s.maxIDsPerVault > 0 && len(v) >= s.maxIDsPerVault {
			return ErrTooManyAttachments
		}
		if err := os.MkdirAll(s.attachmentsDir(a), 0o700); err != nil {
			return err
		}
		e = &fsEntry{total: total}
		v[id] = e
		// Persist at upload-start so a restart still counts this id against
		// the per-vault ceiling (half-finished uploads are the OOM/disk vector).
		if err := s.persist(a); err != nil {
			delete(v, id)
			return err
		}
	}
	if e.total != total {
		return ErrDeclaredLen
	}
	if e.complete {
		// Idempotent no-op replay of a completed upload's chunk is not
		// supported at the byte layer — the client HEAD-probes first.
		return ErrBadOffset
	}
	if offset != e.uploaded {
		return ErrBadOffset
	}
	if e.uploaded+len(chunk) > total {
		return ErrRangeOOB
	}
	f, err := os.OpenFile(s.partialPath(a, id), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(chunk); err != nil {
		_ = f.Close()
		return err
	}
	// No per-chunk fsync (see the type doc): a lost tail self-heals via the
	// HEAD re-probe; integrity is the client's whole-blob tag.
	if err := f.Close(); err != nil {
		return err
	}
	e.uploaded += len(chunk)
	s.accountBytes[a] += uint64(len(chunk))
	if e.uploaded == total {
		if err := s.finalize(a, id); err != nil {
			return err
		}
		e.complete = true
		if err := s.persist(a); err != nil {
			return err
		}
	}
	return nil
}

// ReadRange serves bytes [start, start+length) of a complete attachment.
func (s *FSStore) ReadRange(a ids.AccountNumberHash, id AttachmentID, start, length int) ([]byte, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.vaults[a][id]
	if e == nil || !e.complete || e.deleted {
		return nil, 0, ErrNotFound
	}
	if start < 0 || start > e.uploaded {
		return nil, 0, ErrRangeOOB
	}
	end := start + length
	if length <= 0 || end > e.uploaded {
		end = e.uploaded
	}
	f, err := os.Open(s.finalPath(a, id))
	if err != nil {
		return nil, 0, ErrNotFound
	}
	defer func() { _ = f.Close() }()
	out := make([]byte, end-start)
	if _, err := f.ReadAt(out, int64(start)); err != nil && end > start {
		return nil, 0, ErrRangeOOB
	}
	return out, e.uploaded, nil
}

// AccountBytes is the account's live attachment byte total (rebuilt from disk
// at load — restart-proof unified AS17 accounting).
func (s *FSStore) AccountBytes(a ids.AccountNumberHash) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accountBytes[a]
}

// MarkDeleted hides the body without dropping it (§11.4); persisted so the
// deleted-is-absent state survives a restart.
func (s *FSStore) MarkDeleted(a ids.AccountNumberHash, id AttachmentID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.vaults[a][id]; e != nil && !e.deleted {
		e.deleted = true
		_ = s.persist(a)
	}
}

// Reclaim physically drops the body + partial state and frees the id slot.
func (s *FSStore) Reclaim(a ids.AccountNumberHash, id AttachmentID) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	freed, ok := s.reclaimLocked(a, id)
	if ok {
		_ = s.persist(a)
	}
	return freed, ok
}

// reclaimLocked drops files + counters without persisting. Callers hold mu.
func (s *FSStore) reclaimLocked(a ids.AccountNumberHash, id AttachmentID) (uint64, bool) {
	v := s.vault(a)
	e := v[id]
	if e == nil {
		return 0, false
	}
	if err := os.Remove(s.finalPath(a, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, false
	}
	if err := os.Remove(s.partialPath(a, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, false
	}
	freed := uint64(e.uploaded)
	if s.accountBytes[a] >= freed {
		s.accountBytes[a] -= freed
	} else {
		s.accountBytes[a] = 0
	}
	delete(v, id)
	return freed, true
}

// compile-time assertion that FSStore implements Backend.
var _ Backend = (*FSStore)(nil)
