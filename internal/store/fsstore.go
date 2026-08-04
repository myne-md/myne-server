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
//
// Locking is PER VAULT, not per store: s.mu guards only the `vaults` map (a map
// lookup, never IO), and each fsVault carries the lock covering its own fields and
// its own disk writes. Independent vaults have no reason to serialize against each
// other, and a store-wide lock is what turns one account's slow import into an
// availability event for every other account on the deployment. The two levels are
// never held nested — a resolver releases s.mu before its caller takes v.mu — so
// there is no lock order to get wrong.
type FSStore struct {
	mu     sync.RWMutex // guards `vaults` (the map itself) ONLY
	root   string
	vaults map[ids.AccountNumberHash]*fsVault
	// writeIndex is the durable index-write primitive (default atomicWrite).
	// Injectable so a test can count how many physical writes a batch of mutations
	// coalesced into — the accounts.Store / authpersist discipline.
	writeIndex func(path string, data []byte) error
}

// fsVault is one vault's in-memory metadata index. Ciphertext is on disk; head
// and meta records are read from disk on demand (rare, small).
type fsVault struct {
	mu sync.RWMutex // guards every field below AND this vault's disk writes

	// deleted is set by DeleteAccount after it drops the vault from the map, so a
	// mutation that was already resolving this pointer refuses instead of writing
	// the account's files back into existence.
	deleted bool

	// batchDepth > 0 means a Batch is open over this vault: persist only marks
	// `dirty` and the outermost Batch performs the single coalesced write.
	batchDepth int
	dirty      bool

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
	s := &FSStore{
		root:       dir,
		vaults:     make(map[ids.AccountNumberHash]*fsVault),
		writeIndex: atomicWrite,
	}
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

// DeleteAccount removes the account's entire on-disk vault dir (blobs + meta + head
// + index + tombstones + the attachments subtree — all under one account dir) and its
// in-memory index. Irreversible (MYND-506). Idempotent: RemoveAll on a missing dir is
// a no-op, and deleting an absent map key is a no-op.
//
// The map entry goes first so no new caller can resolve this vault; the tombstoning
// flag + RemoveAll then run under the vault's own lock, which is what orders this
// against an in-flight mutation. A mutation that already held v.mu completes and has
// its files removed; one that arrives afterwards sees `deleted` and refuses, so
// nothing writes a deleted account's files back into existence.
func (s *FSStore) DeleteAccount(account ids.AccountNumberHash) error {
	s.mu.Lock()
	v := s.vaults[account]
	delete(s.vaults, account)
	s.mu.Unlock()

	if v == nil {
		return os.RemoveAll(s.vaultDir(account))
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.deleted = true
	v.dirty = false
	return os.RemoveAll(s.vaultDir(account))
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

// persist records that the vault's metadata index needs writing. Outside a batch
// that means writing it now; inside one it only marks the vault dirty and the
// outermost Batch performs the single coalesced write. Callers hold v.mu.
//
// The distinction is the whole fix for the quadratic push (#6): toIndex() rebuilds
// EVERY blob's metadata and json.Marshal sorts the map's keys, so a per-mutation
// write costs O(i log i) at the i-th blob — Σ over one N-blob request is O(N² log N)
// serialization plus 2N fsyncs, against a payload that is O(N).
func (s *FSStore) persist(a ids.AccountNumberHash, v *fsVault) error {
	if v.batchDepth > 0 {
		v.dirty = true
		return nil
	}
	return s.writeIndexNow(a, v)
}

// writeIndexNow serializes and durably writes the vault's index. Callers hold v.mu.
func (s *FSStore) writeIndexNow(a ids.AccountNumberHash, v *fsVault) error {
	raw, err := json.Marshal(v.toIndex())
	if err != nil {
		return err
	}
	if err := s.writeIndex(filepath.Join(s.vaultDir(a), "index.json"), raw); err != nil {
		return err
	}
	v.dirty = false
	return nil
}

// Batch coalesces every index write the mutations inside fn would each perform
// into one write at the end. See BlobStore.Batch for the contract; the two points
// that matter here are that v.mu is NOT held across fn (the calls inside it take
// that lock themselves, and the push handler additionally reads QuotaBytes between
// them) and that the coalesced write happens even when fn fails, because the
// in-memory index has already advanced and must not run ahead of disk.
//
// It materializes the vault up front rather than lazily, because the batch flag has
// to exist before the first mutation consults it — and a brand-new account's first
// sync is exactly the case this fix is for. A batch that then mutates nothing leaves
// an empty in-memory vault: never written to disk (nothing marked it dirty), gone on
// restart, and reachable only by an already-enrolled device.
func (s *FSStore) Batch(account ids.AccountNumberHash, fn func() error) error {
	v := s.vaultFor(account)

	v.mu.Lock()
	v.batchDepth++
	v.mu.Unlock()

	ferr := fn()

	v.mu.Lock()
	v.batchDepth--
	var werr error
	if v.batchDepth == 0 && v.dirty && !v.deleted {
		werr = s.writeIndexNow(account, v)
	}
	v.mu.Unlock()

	if ferr != nil {
		return ferr
	}
	return werr
}

func newFSVault() *fsVault {
	return &fsVault{
		blobs:      make(map[ids.BlobID]*fsBlobMeta),
		cursors:    make(map[ids.DeviceID]uint64),
		tombstones: make(map[ids.BlobID]*tombstoneRec),
	}
}

// lookupVault returns the account's vault, or nil if it has none. It never
// creates one — the read paths must not materialize a vault for an unknown
// account. Returns with s.mu released, so the caller takes v.mu unnested.
func (s *FSStore) lookupVault(a ids.AccountNumberHash) *fsVault {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.vaults[a]
}

// vaultFor returns the account's vault, creating it if absent. Returns with s.mu
// released, so the caller takes v.mu unnested.
func (s *FSStore) vaultFor(a ids.AccountNumberHash) *fsVault {
	if v := s.lookupVault(a); v != nil {
		return v
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vaults[a]
	if v == nil {
		v = newFSVault()
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
	v := s.vaultFor(account)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.deleted {
		return 0, ErrNotFound
	}
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
	v := s.vaultFor(account)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.deleted {
		return 0, ErrNotFound
	}
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
	// A new content version supersedes any recorded deletion (§11.1): clear the
	// reclaimed mark AND the tombstone record so a later GC pass cannot reclaim
	// the resurrected body, and the record re-enters the manifest.
	m.reclaimed = false
	delete(v.tombstones, blobID)
	v.seq++
	m.changeSeq = v.seq
	if err := s.persist(account, v); err != nil {
		return 0, err
	}
	return m.version, nil
}

func (s *FSStore) GetBlob(account ids.AccountNumberHash, blobID ids.BlobID) ([]byte, Version, error) {
	v := s.lookupVault(account)
	if v == nil {
		return nil, 0, ErrNotFound
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	m := v.blobs[blobID]
	if m == nil {
		return nil, 0, ErrNotFound
	}
	// A Layer-2 reclaimed blob's body is gone from disk; ErrReclaimed keeps it
	// from reading as a live empty ciphertext (a puller would write 0 bytes
	// over a real note).
	if m.reclaimed {
		return nil, m.version, ErrReclaimed
	}
	return s.readBody(account, blobID), m.version, nil
}

func (s *FSStore) BlobVersion(account ids.AccountNumberHash, blobID ids.BlobID) (Version, error) {
	v := s.lookupVault(account)
	if v == nil {
		return 0, ErrNotFound
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	m := v.blobs[blobID]
	if m == nil {
		return 0, ErrNotFound
	}
	return m.version, nil
}

func (s *FSStore) GetHead(account ids.AccountNumberHash) ([]byte, [HeadIDLen]byte, error) {
	var zero [HeadIDLen]byte
	v := s.lookupVault(account)
	if v == nil {
		return nil, zero, ErrNotFound
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if !v.hasHead {
		return nil, zero, ErrNotFound
	}
	data, err := os.ReadFile(filepath.Join(s.vaultDir(account), "head"))
	if err != nil {
		return nil, zero, ErrNotFound
	}
	return data, v.headID, nil
}

func (s *FSStore) AdvanceHead(account ids.AccountNumberHash, prevHeadHash [HeadIDLen]byte, record []byte) ([HeadIDLen]byte, error) {
	var zero [HeadIDLen]byte
	v := s.vaultFor(account)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.deleted {
		return zero, ErrNotFound
	}
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

func (s *FSStore) SetMeta(account ids.AccountNumberHash, meta []byte) error {
	v := s.vaultFor(account)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.deleted {
		return ErrNotFound
	}
	if err := atomicWrite(filepath.Join(s.vaultDir(account), "meta"), meta); err != nil {
		return err
	}
	return s.persist(account, v) // ensure the vault dir/index exists
}

func (s *FSStore) GetMeta(account ids.AccountNumberHash) ([]byte, error) {
	if s.lookupVault(account) == nil {
		return nil, ErrNotFound
	}
	data, err := os.ReadFile(filepath.Join(s.vaultDir(account), "meta"))
	if err != nil {
		return nil, ErrNotFound
	}
	return data, nil
}

func (s *FSStore) QuotaBytes(account ids.AccountNumberHash) uint64 {
	v := s.lookupVault(account)
	if v == nil {
		return 0
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.quotaBytes
}

// BlobQuotaBytes answers from the in-memory index — the recorded size is the same
// figure PushBlob nets out of quotaBytes, so no body read is needed.
func (s *FSStore) BlobQuotaBytes(account ids.AccountNumberHash, blobID ids.BlobID) uint64 {
	v := s.lookupVault(account)
	if v == nil {
		return 0
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	m := v.blobs[blobID]
	if m == nil {
		return 0
	}
	return uint64(m.size)
}

// ChangedSince selects its window over ALL entries (live + reclaimed) so the
// cursor advances across reclaimed records, then emits only live ones — a
// reclaimed uuid is manifest-absent (§11.3), never a size-0 meta. See the
// MemStore counterpart for why filtering the window instead wedges the cursor
// below the reclaim floor.
func (s *FSStore) ChangedSince(account ids.AccountNumberHash, cursor uint64, limit int) ([]SyncMeta, uint64) {
	v := s.lookupVault(account)
	if v == nil {
		return nil, cursor
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
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
		if it.m.changeSeq > newCursor {
			newCursor = it.m.changeSeq
		}
		if it.m.reclaimed {
			continue
		}
		out = append(out, SyncMeta{BlobID: it.id, Version: it.m.version, ContentNonce: it.m.contentNonce, Size: it.m.size, AttachmentIDHex: it.m.attachmentID})
	}
	return out, newCursor
}

// SetBlobAttachmentID associates the full attachment-id (hex) with a blob record
// (MYND-468), persisted in the vault index. See BlobStore.SetBlobAttachmentID.
func (s *FSStore) SetBlobAttachmentID(account ids.AccountNumberHash, blobID ids.BlobID, attachmentIDHex string) error {
	v := s.lookupVault(account)
	if v == nil {
		return ErrNotFound
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.deleted {
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
	v := s.lookupVault(account)
	if v == nil {
		return ""
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	m := v.blobs[blobID]
	if m == nil {
		return ""
	}
	return m.attachmentID
}

func (s *FSStore) AckCursor(account ids.AccountNumberHash, device ids.DeviceID, pos uint64) {
	v := s.vaultFor(account)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.deleted {
		return
	}
	if pos > v.cursors[device] {
		v.cursors[device] = pos
		_ = s.persist(account, v)
	}
}

func (s *FSStore) DeviceCursor(account ids.AccountNumberHash, device ids.DeviceID) uint64 {
	v := s.lookupVault(account)
	if v == nil {
		return 0
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.cursors[device]
}

func (s *FSStore) SetTombstone(account ids.AccountNumberHash, blobID ids.BlobID, finalVersion Version) error {
	v := s.vaultFor(account)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.deleted {
		return ErrNotFound
	}
	seq := uint64(0)
	if m := v.blobs[blobID]; m != nil {
		seq = m.changeSeq
	}
	v.tombstones[blobID] = &tombstoneRec{finalVersion: finalVersion, changeSeq: seq}
	return s.persist(account, v)
}

func (s *FSStore) Tombstone(account ids.AccountNumberHash, blobID ids.BlobID) (Version, bool) {
	v := s.lookupVault(account)
	if v == nil {
		return 0, false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	rec, ok := v.tombstones[blobID]
	if !ok {
		return 0, false
	}
	return rec.finalVersion, true
}

func (s *FSStore) TombstoneRecord(account ids.AccountNumberHash, blobID ids.BlobID) (Version, uint64, bool, bool) {
	v := s.lookupVault(account)
	if v == nil {
		return 0, 0, false, false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	rec, ok := v.tombstones[blobID]
	if !ok {
		return 0, 0, false, false
	}
	return rec.finalVersion, rec.changeSeq, rec.reclaimed, true
}

func (s *FSStore) ListTombstones(account ids.AccountNumberHash) []ids.BlobID {
	v := s.lookupVault(account)
	if v == nil {
		return nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
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
	v := s.lookupVault(account)
	if v == nil {
		return ErrNotFound
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.deleted {
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
	v := s.lookupVault(account)
	if v == nil {
		return 0
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.reclaimFloor
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
