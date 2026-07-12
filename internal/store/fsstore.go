// SPDX-License-Identifier: AGPL-3.0

package store

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/myne-md/myne-server/internal/headid"
	"github.com/myne-md/myne-server/internal/ids"
)

// FSStore is a durable, single-volume filesystem BlobStore (MYND-438, SYNC-22).
// It is the production self-host backend behind the same BlobStore seam as the
// reference MemStore — identical semantics, persisted to one mounted volume so a
// backup is a single consistent snapshot (blobs + metadata + head together).
//
// Layout (per-vault namespace keyed on account_number_hash — NO global content-
// addressed bucket, §2.1):
//
//	<root>/<account_hex>/blobs/<blobid_hex>   opaque ciphertext body (one file/blob)
//	<root>/<account_hex>/head                 opaque vault-head record (CAS target)
//	<root>/<account_hex>/meta                 opaque AEAD vault.meta blob
//	<root>/<account_hex>/index.json           per-vault metadata index (see vaultIndex)
//
// Ciphertext bodies live on disk (NOT in memory) so a 64 MiB attachment does not
// inflate RSS — only the small metadata index is held in memory. All writes are
// atomic-rename (write-temp + fsync + rename + dir-fsync) so a crashed/interrupted
// write leaves the prior bytes intact (old-or-new-never-partial): a live `cp -r`
// of the volume is always restorable. The seam stays FS-agnostic (opaque
// get/put/delete by namespaced key) so an S3 backend can drop in later.
type FSStore struct {
	mu     sync.RWMutex
	root   string
	vaults map[ids.AccountNumberHash]*fsVault
}

// fsVault is one vault's in-memory metadata index. Ciphertext is on disk; head
// and meta records are read from disk on demand (rare, small).
type fsVault struct {
	blobs        map[ids.BlobID]*fsBlobMeta
	headID       [HeadIDLen]byte
	hasHead      bool
	quotaBytes   uint64
	seq          uint64
	cursors      map[ids.DeviceID]uint64
	tombstones   map[ids.BlobID]*tombstoneRec
	reclaimFloor uint64
}

type fsBlobMeta struct {
	version      Version
	contentNonce [ContentNonceLen]byte
	size         int
	changeSeq    uint64
	reclaimed    bool // L2-reclaimed → body removed from disk
	// attachmentID is the full 32-byte attachment-id (hex) for an attachment
	// record (MYND-468); "" for notes. Opaque; echoed in ChangedSince.
	attachmentID string
}

// NewFSStore opens (creating if absent) a filesystem store rooted at dir and loads
// every existing vault's metadata index into memory. Ciphertext is left on disk.
func NewFSStore(dir string) (*FSStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &FSStore{root: dir, vaults: make(map[ids.AccountNumberHash]*fsVault)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// --- on-disk index encoding -------------------------------------------------

type vaultIndex struct {
	Blobs        map[string]blobIndex `json:"blobs"`
	HeadID       string               `json:"head_id,omitempty"` // base64
	HasHead      bool                 `json:"has_head"`
	QuotaBytes   uint64               `json:"quota_bytes"`
	Seq          uint64               `json:"seq"`
	Cursors      map[string]uint64    `json:"cursors,omitempty"` // device_hex -> pos
	ReclaimFloor uint64               `json:"reclaim_floor"`
	Tombstones   map[string]tombIndex `json:"tombstones,omitempty"`
}

type blobIndex struct {
	Version      Version `json:"version"`
	ContentNonce string  `json:"content_nonce"` // base64
	Size         int     `json:"size"`
	ChangeSeq    uint64  `json:"change_seq"`
	Reclaimed    bool    `json:"reclaimed,omitempty"`
	AttachmentID string  `json:"attachment_id,omitempty"` // full 32-byte id, hex (MYND-468)
}

type tombIndex struct {
	FinalVersion Version `json:"final_version"`
	ChangeSeq    uint64  `json:"change_seq"`
	Reclaimed    bool    `json:"reclaimed,omitempty"`
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

		idxPath := filepath.Join(s.root, ent.Name(), "index.json")
		raw, err := os.ReadFile(idxPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		var idx vaultIndex
		if err := json.Unmarshal(raw, &idx); err != nil {
			return err
		}
		s.vaults[acct] = idx.toVault()
	}
	return nil
}

func (idx vaultIndex) toVault() *fsVault {
	v := &fsVault{
		blobs:        make(map[ids.BlobID]*fsBlobMeta, len(idx.Blobs)),
		hasHead:      idx.HasHead,
		quotaBytes:   idx.QuotaBytes,
		seq:          idx.Seq,
		cursors:      make(map[ids.DeviceID]uint64, len(idx.Cursors)),
		tombstones:   make(map[ids.BlobID]*tombstoneRec, len(idx.Tombstones)),
		reclaimFloor: idx.ReclaimFloor,
	}
	if idx.HeadID != "" {
		if b, err := base64.StdEncoding.DecodeString(idx.HeadID); err == nil && len(b) == HeadIDLen {
			copy(v.headID[:], b)
		}
	}
	for k, b := range idx.Blobs {
		id, ok := decodeBlobID(k)
		if !ok {
			continue
		}
		m := &fsBlobMeta{version: b.Version, size: b.Size, changeSeq: b.ChangeSeq, reclaimed: b.Reclaimed, attachmentID: b.AttachmentID}
		if nb, err := base64.StdEncoding.DecodeString(b.ContentNonce); err == nil && len(nb) == ContentNonceLen {
			copy(m.contentNonce[:], nb)
		}
		v.blobs[id] = m
	}
	for k, pos := range idx.Cursors {
		if d, ok := decodeDeviceID(k); ok {
			v.cursors[d] = pos
		}
	}
	for k, t := range idx.Tombstones {
		if id, ok := decodeBlobID(k); ok {
			v.tombstones[id] = &tombstoneRec{finalVersion: t.FinalVersion, changeSeq: t.ChangeSeq, reclaimed: t.Reclaimed}
		}
	}
	return v
}

func (v *fsVault) toIndex() vaultIndex {
	idx := vaultIndex{
		Blobs:        make(map[string]blobIndex, len(v.blobs)),
		HasHead:      v.hasHead,
		QuotaBytes:   v.quotaBytes,
		Seq:          v.seq,
		Cursors:      make(map[string]uint64, len(v.cursors)),
		ReclaimFloor: v.reclaimFloor,
		Tombstones:   make(map[string]tombIndex, len(v.tombstones)),
	}
	if v.hasHead {
		idx.HeadID = base64.StdEncoding.EncodeToString(v.headID[:])
	}
	for id, m := range v.blobs {
		idx.Blobs[hex.EncodeToString(id[:])] = blobIndex{
			Version:      m.version,
			ContentNonce: base64.StdEncoding.EncodeToString(m.contentNonce[:]),
			Size:         m.size,
			ChangeSeq:    m.changeSeq,
			Reclaimed:    m.reclaimed,
			AttachmentID: m.attachmentID,
		}
	}
	for d, pos := range v.cursors {
		idx.Cursors[hex.EncodeToString(d[:])] = pos
	}
	for id, t := range v.tombstones {
		idx.Tombstones[hex.EncodeToString(id[:])] = tombIndex{FinalVersion: t.finalVersion, ChangeSeq: t.changeSeq, Reclaimed: t.reclaimed}
	}
	return idx
}

// --- paths + atomic IO ------------------------------------------------------

func (s *FSStore) vaultDir(a ids.AccountNumberHash) string {
	return filepath.Join(s.root, hex.EncodeToString(a[:]))
}
func (s *FSStore) blobPath(a ids.AccountNumberHash, b ids.BlobID) string {
	return filepath.Join(s.vaultDir(a), "blobs", hex.EncodeToString(b[:]))
}

// atomicWrite writes data to path via temp+fsync+rename+dir-fsync so an
// interrupted write never leaves a partial file (old-or-new-never-partial).
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op if the rename succeeded
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// AtomicWrite durably writes data to path (temp + fsync + rename + parent-dir fsync) —
// the same audited primitive index.json / head / blob bodies use. Exposed so the auth
// persistence layer shares ONE write path instead of forking a second copy. The file
// lands at 0600 (os.CreateTemp's temp mode survives the rename); the explicit Chmod
// pins that guarantee independent of the process umask, because this file holds bearer
// tokens + SCRAM verifiers.
func AtomicWrite(path string, data []byte) error {
	if err := atomicWrite(path, data); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// persist writes the vault's metadata index atomically. Callers hold mu.
func (s *FSStore) persist(a ids.AccountNumberHash, v *fsVault) error {
	raw, err := json.Marshal(v.toIndex())
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.vaultDir(a), "index.json"), raw)
}

func (s *FSStore) vault(a ids.AccountNumberHash) *fsVault {
	v := s.vaults[a]
	if v == nil {
		v = &fsVault{
			blobs:      make(map[ids.BlobID]*fsBlobMeta),
			cursors:    make(map[ids.DeviceID]uint64),
			tombstones: make(map[ids.BlobID]*tombstoneRec),
		}
		s.vaults[a] = v
	}
	return v
}

func decodeBlobID(s string) (ids.BlobID, bool) {
	var id ids.BlobID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ids.BlobIDLen {
		return id, false
	}
	copy(id[:], b)
	return id, true
}
func decodeDeviceID(s string) (ids.DeviceID, bool) {
	var d ids.DeviceID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ids.DeviceIDLen {
		return d, false
	}
	copy(d[:], b)
	return d, true
}

// readBody returns the on-disk ciphertext for a blob, or nil if absent/reclaimed.
func (s *FSStore) readBody(a ids.AccountNumberHash, b ids.BlobID) []byte {
	data, err := os.ReadFile(s.blobPath(a, b))
	if err != nil {
		return nil
	}
	return data
}

// --- BlobStore implementation ----------------------------------------------

func (s *FSStore) PutBlob(account ids.AccountNumberHash, blobID ids.BlobID, ciphertext []byte) (Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vault(account)
	m := v.blobs[blobID]
	if m != nil && !m.reclaimed && bytesEqual(s.readBody(account, blobID), ciphertext) {
		return m.version, nil // idempotent re-put
	}
	// Write the body FIRST: a failed write (e.g. ENOSPC) returns cleanly and leaves
	// the in-memory index + the prior body untouched (graceful ENOSPC, SYNC-23).
	if err := atomicWrite(s.blobPath(account, blobID), ciphertext); err != nil {
		return 0, err
	}
	if m == nil {
		m = &fsBlobMeta{}
		v.blobs[blobID] = m
	}
	v.quotaBytes = v.quotaBytes - uint64(m.size) + uint64(len(ciphertext))
	m.version++
	m.size = len(ciphertext)
	m.reclaimed = false
	v.seq++
	m.changeSeq = v.seq
	if err := s.persist(account, v); err != nil {
		return 0, err
	}
	return m.version, nil
}

func (s *FSStore) PushBlob(account ids.AccountNumberHash, blobID ids.BlobID, baseVersion Version, contentNonce [ContentNonceLen]byte, ciphertext []byte) (Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vault(account)
	m := v.blobs[blobID]
	cur := Version(0)
	if m != nil {
		cur = m.version
	}
	if baseVersion != cur {
		if m != nil && m.version == baseVersion+1 && !m.reclaimed &&
			m.contentNonce == contentNonce && bytesEqual(s.readBody(account, blobID), ciphertext) {
			return m.version, nil // idempotent replay
		}
		return 0, ErrBlobCASMismatch
	}
	// Idempotent re-push at the current base requires identical bytes AND an
	// identical nonce — for an attachment record (empty inline ciphertext,
	// MYND-468) the nonce is the only discriminator between a registration and
	// its tombstone, and absorbing the nonce change would hide the deletion
	// from every other device's change feed.
	if m != nil && m.version != 0 && !m.reclaimed && m.contentNonce == contentNonce &&
		bytesEqual(s.readBody(account, blobID), ciphertext) {
		return m.version, nil
	}
	// Write the body FIRST (graceful ENOSPC, SYNC-23): a failed write leaves the
	// in-memory index + prior body untouched.
	if err := atomicWrite(s.blobPath(account, blobID), ciphertext); err != nil {
		return 0, err
	}
	if m == nil {
		m = &fsBlobMeta{}
		v.blobs[blobID] = m
	}
	v.quotaBytes = v.quotaBytes - uint64(m.size) + uint64(len(ciphertext))
	m.contentNonce = contentNonce
	m.size = len(ciphertext)
	m.version++
	m.reclaimed = false
	v.seq++
	m.changeSeq = v.seq
	if err := s.persist(account, v); err != nil {
		return 0, err
	}
	return m.version, nil
}

func (s *FSStore) GetBlob(account ids.AccountNumberHash, blobID ids.BlobID) ([]byte, Version, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.vaults[account]
	if v == nil {
		return nil, 0, ErrNotFound
	}
	m := v.blobs[blobID]
	if m == nil {
		return nil, 0, ErrNotFound
	}
	return s.readBody(account, blobID), m.version, nil
}

func (s *FSStore) BlobVersion(account ids.AccountNumberHash, blobID ids.BlobID) (Version, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.vaults[account]
	if v == nil {
		return 0, ErrNotFound
	}
	m := v.blobs[blobID]
	if m == nil {
		return 0, ErrNotFound
	}
	return m.version, nil
}

func (s *FSStore) GetHead(account ids.AccountNumberHash) ([]byte, [HeadIDLen]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var zero [HeadIDLen]byte
	v := s.vaults[account]
	if v == nil || !v.hasHead {
		return nil, zero, ErrNotFound
	}
	data, err := os.ReadFile(filepath.Join(s.vaultDir(account), "head"))
	if err != nil {
		return nil, zero, ErrNotFound
	}
	return data, v.headID, nil
}

func (s *FSStore) AdvanceHead(account ids.AccountNumberHash, prevHeadHash [HeadIDLen]byte, record []byte) ([HeadIDLen]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var zero [HeadIDLen]byte
	v := s.vault(account)
	if v.hasHead {
		if prevHeadHash != v.headID {
			return zero, ErrHeadCASMismatch
		}
	} else if prevHeadHash != genesisPrevHash {
		return zero, ErrHeadCASMismatch
	}
	if err := atomicWrite(filepath.Join(s.vaultDir(account), "head"), record); err != nil {
		return zero, err
	}
	newID := headid.Compute(record)
	v.headID = newID
	v.hasHead = true
	if err := s.persist(account, v); err != nil {
		return zero, err
	}
	return newID, nil
}

func (s *FSStore) SetMeta(account ids.AccountNumberHash, meta []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vault(account)
	_ = atomicWrite(filepath.Join(s.vaultDir(account), "meta"), meta)
	_ = s.persist(account, v) // ensure the vault dir/index exists
}

func (s *FSStore) GetMeta(account ids.AccountNumberHash) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.vaults[account] == nil {
		return nil, ErrNotFound
	}
	data, err := os.ReadFile(filepath.Join(s.vaultDir(account), "meta"))
	if err != nil {
		return nil, ErrNotFound
	}
	return data, nil
}

func (s *FSStore) QuotaBytes(account ids.AccountNumberHash) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v := s.vaults[account]; v != nil {
		return v.quotaBytes
	}
	return 0
}

func (s *FSStore) ChangedSince(account ids.AccountNumberHash, cursor uint64, limit int) ([]SyncMeta, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.vaults[account]
	if v == nil {
		return nil, cursor
	}
	type item struct {
		id ids.BlobID
		m  *fsBlobMeta
	}
	var items []item
	for id, m := range v.blobs {
		if m.changeSeq > cursor {
			items = append(items, item{id, m})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].m.changeSeq < items[j].m.changeSeq })
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	newCursor := cursor
	out := make([]SyncMeta, 0, len(items))
	for _, it := range items {
		out = append(out, SyncMeta{BlobID: it.id, Version: it.m.version, ContentNonce: it.m.contentNonce, Size: it.m.size, AttachmentIDHex: it.m.attachmentID})
		if it.m.changeSeq > newCursor {
			newCursor = it.m.changeSeq
		}
	}
	return out, newCursor
}

// SetBlobAttachmentID associates the full attachment-id (hex) with a blob record
// (MYND-468), persisted in the vault index. See BlobStore.SetBlobAttachmentID.
func (s *FSStore) SetBlobAttachmentID(account ids.AccountNumberHash, blobID ids.BlobID, attachmentIDHex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vaults[account]
	if v == nil {
		return ErrNotFound
	}
	m := v.blobs[blobID]
	if m == nil {
		return ErrNotFound
	}
	if m.attachmentID == attachmentIDHex {
		return nil // no index churn on an idempotent re-push
	}
	m.attachmentID = attachmentIDHex
	return s.persist(account, v)
}

// BlobAttachmentID returns the associated attachment-id hex ("" if none).
func (s *FSStore) BlobAttachmentID(account ids.AccountNumberHash, blobID ids.BlobID) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.vaults[account]
	if v == nil {
		return ""
	}
	m := v.blobs[blobID]
	if m == nil {
		return ""
	}
	return m.attachmentID
}

func (s *FSStore) AckCursor(account ids.AccountNumberHash, device ids.DeviceID, pos uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vault(account)
	if pos > v.cursors[device] {
		v.cursors[device] = pos
		_ = s.persist(account, v)
	}
}

func (s *FSStore) DeviceCursor(account ids.AccountNumberHash, device ids.DeviceID) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v := s.vaults[account]; v != nil {
		return v.cursors[device]
	}
	return 0
}

func (s *FSStore) SetTombstone(account ids.AccountNumberHash, blobID ids.BlobID, finalVersion Version) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vault(account)
	seq := uint64(0)
	if m := v.blobs[blobID]; m != nil {
		seq = m.changeSeq
	}
	v.tombstones[blobID] = &tombstoneRec{finalVersion: finalVersion, changeSeq: seq}
	return s.persist(account, v)
}

func (s *FSStore) Tombstone(account ids.AccountNumberHash, blobID ids.BlobID) (Version, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.vaults[account]
	if v == nil {
		return 0, false
	}
	rec, ok := v.tombstones[blobID]
	if !ok {
		return 0, false
	}
	return rec.finalVersion, true
}

func (s *FSStore) TombstoneRecord(account ids.AccountNumberHash, blobID ids.BlobID) (Version, uint64, bool, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.vaults[account]
	if v == nil {
		return 0, 0, false, false
	}
	rec, ok := v.tombstones[blobID]
	if !ok {
		return 0, 0, false, false
	}
	return rec.finalVersion, rec.changeSeq, rec.reclaimed, true
}

func (s *FSStore) ListTombstones(account ids.AccountNumberHash) []ids.BlobID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.vaults[account]
	if v == nil {
		return nil
	}
	out := make([]ids.BlobID, 0, len(v.tombstones))
	for id := range v.tombstones {
		out = append(out, id)
	}
	return out
}

// ReclaimTombstone drops the ciphertext body from disk (Layer-2 reclamation) and
// keeps (uuid, final_version, marker). Removing the file on disk — not just a
// marker — is the load-bearing FS reclamation (SYNC-22): the bytes are gone.
func (s *FSStore) ReclaimTombstone(account ids.AccountNumberHash, blobID ids.BlobID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vaults[account]
	if v == nil {
		return ErrNotFound
	}
	rec, ok := v.tombstones[blobID]
	if !ok {
		return ErrNotFound
	}
	if m := v.blobs[blobID]; m != nil {
		v.quotaBytes -= uint64(m.size)
		m.size = 0
		m.reclaimed = true
		if err := os.Remove(s.blobPath(account, blobID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	rec.reclaimed = true
	if rec.changeSeq > v.reclaimFloor {
		v.reclaimFloor = rec.changeSeq
	}
	return s.persist(account, v)
}

func (s *FSStore) GCFloor(account ids.AccountNumberHash) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v := s.vaults[account]; v != nil {
		return v.reclaimFloor
	}
	return 0
}

// ListAccounts returns every account namespace present (for the GC scheduler,
// MYND-440) — opaque account_number_hash keys only.
func (s *FSStore) ListAccounts() []ids.AccountNumberHash {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ids.AccountNumberHash, 0, len(s.vaults))
	for a := range s.vaults {
		out = append(out, a)
	}
	return out
}

// compile-time assertion that FSStore implements BlobStore.
var _ BlobStore = (*FSStore)(nil)
