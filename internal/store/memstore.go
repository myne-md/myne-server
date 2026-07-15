// SPDX-License-Identifier: AGPL-3.0

package store

import (
	"sort"
	"sync"

	"github.com/myne-md/myne-server/internal/headid"
	"github.com/myne-md/myne-server/internal/ids"
)

// MemStore is the in-memory reference BlobStore for the bootstrap skeleton.
// It isolates vaults by account_number_hash and stores ciphertext opaquely.
// A production backend (FS/SQL) implements the same interface later
// (MYND-421/438) without changing callers.
type MemStore struct {
	mu     sync.RWMutex
	vaults map[ids.AccountNumberHash]*vaultState
}

// vaultState is one vault's namespace. The GC/quota substrate (task 7) is added here.
type vaultState struct {
	blobs map[ids.BlobID]*blobEntry

	// head is the opaque current vault-head record; headID = SHA-256(head).
	// hasHead is false until the genesis head lands.
	head    []byte
	headID  [HeadIDLen]byte
	hasHead bool

	// meta is the opaque AEAD vault.meta blob (MYND-425 enrollment bootstrap): a
	// new device fetches it (pre-auth, by account_number_hash) to derive root_key
	// before it can SCRAM-auth. AEAD-protected — useless without the password.
	meta []byte

	// GC/quota substrate (policy lives in MYND-422):
	quotaBytes uint64                       // deduplicated stored-ciphertext byte total (AS17)
	tombstones map[ids.BlobID]*tombstoneRec // (uuid → record); presence = tombstone_marker

	// sync (push/pull, MYND-421):
	seq     uint64                  // per-vault monotone change-sequence (cursor space)
	cursors map[ids.DeviceID]uint64 // per-device acked pull cursor (SYNC-6)

	// GC reclaim floor (MYND-422): the highest change-sequence whose tombstone L2
	// has reclaimed. A pull whose cursor is below this missed reclaimed history →
	// the server signals cursor-expired (410) → client full-reconcile (§11.2).
	reclaimFloor uint64
}

type blobEntry struct {
	ciphertext   []byte
	version      Version
	contentNonce [ContentNonceLen]byte
	size         int
	changeSeq    uint64 // per-vault sequence of this blob's last mutation
	// attachmentID is the full 32-byte attachment-id (hex) for an attachment
	// record (MYND-468); "" for notes. Opaque; echoed in ChangedSince.
	attachmentID string
}

// tombstoneRec is the server-side (uuid, final_version, marker) record + the
// change-sequence a device must have acked past, + whether L2 reclaimed the body.
type tombstoneRec struct {
	finalVersion Version
	changeSeq    uint64
	reclaimed    bool
}

// NewMemStore returns an empty in-memory BlobStore.
func NewMemStore() *MemStore {
	return &MemStore{vaults: make(map[ids.AccountNumberHash]*vaultState)}
}

// vault returns (creating if needed) the per-account namespace. Caller holds mu.
func (m *MemStore) vault(account ids.AccountNumberHash) *vaultState {
	v := m.vaults[account]
	if v == nil {
		v = &vaultState{
			blobs:      make(map[ids.BlobID]*blobEntry),
			tombstones: make(map[ids.BlobID]*tombstoneRec),
			cursors:    make(map[ids.DeviceID]uint64),
		}
		m.vaults[account] = v
	}
	return v
}

// PutBlob stores opaque ciphertext and advances the blob's monotonic version
// counter on NEW ciphertext. A re-put of byte-identical ciphertext is idempotent:
// it does not advance the version and returns the current one (content-addressed
// retries are absorbed, ledger SYNC-5). The version is an opaque sync-internal
// counter — never derived from wall-clock, never an API timestamp (AS6).
func (m *MemStore) PutBlob(account ids.AccountNumberHash, blobID ids.BlobID, ciphertext []byte) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v := m.vault(account)
	e := v.blobs[blobID]
	if e == nil {
		e = &blobEntry{}
		v.blobs[blobID] = e
	}
	if e.ciphertext != nil && bytesEqual(e.ciphertext, ciphertext) {
		// Idempotent re-put of identical ciphertext: no new version.
		return e.version, nil
	}
	// Copy in: never alias the caller's buffer (it may be reused). The server
	// holds opaque bytes only — it never inspects them.
	buf := make([]byte, len(ciphertext))
	copy(buf, ciphertext)
	// Quota substrate: adjust the dedup'd byte total by the size delta (one stored
	// blob counted once by its current size).
	v.quotaBytes = v.quotaBytes - uint64(len(e.ciphertext)) + uint64(len(buf))
	e.ciphertext = buf
	e.version++
	e.size = len(buf)
	v.seq++
	e.changeSeq = v.seq
	return e.version, nil
}

// PushBlob stores opaque ciphertext under optimistic CAS on baseVersion, recording
// the client-supplied public content_nonce. See BlobStore.PushBlob.
func (m *MemStore) PushBlob(account ids.AccountNumberHash, blobID ids.BlobID, baseVersion Version, contentNonce [ContentNonceLen]byte, ciphertext []byte) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v := m.vault(account)
	e := v.blobs[blobID]
	cur := Version(0)
	if e != nil {
		cur = e.version
	}
	if baseVersion != cur {
		// Idempotent replay: a retry arrives with the OLD base, but the exact push
		// it carries (content + nonce) already applied (current = base+1). Absorb it
		// (CAS + content-addressing, ledger SYNC-5). Otherwise it is a real stale base.
		if e != nil && e.version == baseVersion+1 &&
			bytesEqual(e.ciphertext, ciphertext) && e.contentNonce == contentNonce {
			return e.version, nil
		}
		return 0, ErrBlobCASMismatch
	}
	if e == nil {
		e = &blobEntry{}
		v.blobs[blobID] = e
	}
	// Idempotent re-push at the current base: identical bytes AND an identical
	// nonce → no new version. The nonce equality is load-bearing for attachment
	// records (MYND-468): their inline ciphertext is ALWAYS empty, so the nonce
	// is the only thing distinguishing a registration from its §11.4 tombstone —
	// absorbing a nonce-different push would never advance the change-sequence
	// and other devices would never see the deletion.
	if e.ciphertext != nil && bytesEqual(e.ciphertext, ciphertext) && e.contentNonce == contentNonce {
		return e.version, nil
	}
	buf := make([]byte, len(ciphertext))
	copy(buf, ciphertext)
	v.quotaBytes = v.quotaBytes - uint64(len(e.ciphertext)) + uint64(len(buf))
	e.ciphertext = buf
	e.contentNonce = contentNonce
	e.size = len(buf)
	e.version++
	v.seq++
	e.changeSeq = v.seq
	return e.version, nil
}

// ChangedSince returns up to limit SyncMeta with change-sequence > cursor, ordered
// by sequence, plus the new cursor.
func (m *MemStore) ChangedSince(account ids.AccountNumberHash, cursor uint64, limit int) ([]SyncMeta, uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v := m.vaults[account]
	if v == nil {
		return nil, cursor
	}
	// Collect blobs with changeSeq > cursor.
	type item struct {
		id ids.BlobID
		e  *blobEntry
	}
	var items []item
	for id, e := range v.blobs {
		if e.changeSeq > cursor {
			items = append(items, item{id: id, e: e})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].e.changeSeq < items[j].e.changeSeq })
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	newCursor := cursor
	out := make([]SyncMeta, 0, len(items))
	for _, it := range items {
		out = append(out, SyncMeta{
			BlobID:          it.id,
			Version:         it.e.version,
			ContentNonce:    it.e.contentNonce,
			Size:            it.e.size,
			AttachmentIDHex: it.e.attachmentID,
		})
		if it.e.changeSeq > newCursor {
			newCursor = it.e.changeSeq
		}
	}
	return out, newCursor
}

// SetBlobAttachmentID associates the full attachment-id (hex) with a blob record
// (MYND-468). See BlobStore.SetBlobAttachmentID.
func (m *MemStore) SetBlobAttachmentID(account ids.AccountNumberHash, blobID ids.BlobID, attachmentIDHex string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.vaults[account]
	if v == nil {
		return ErrNotFound
	}
	e := v.blobs[blobID]
	if e == nil {
		return ErrNotFound
	}
	e.attachmentID = attachmentIDHex
	return nil
}

// BlobAttachmentID returns the associated attachment-id hex ("" if none).
func (m *MemStore) BlobAttachmentID(account ids.AccountNumberHash, blobID ids.BlobID) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v := m.vaults[account]
	if v == nil {
		return ""
	}
	e := v.blobs[blobID]
	if e == nil {
		return ""
	}
	return e.attachmentID
}

// AckCursor records a device's pull cursor position (monotone).
func (m *MemStore) AckCursor(account ids.AccountNumberHash, device ids.DeviceID, pos uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.vault(account)
	if pos > v.cursors[device] {
		v.cursors[device] = pos
	}
}

// DeviceCursor returns a device's last acked cursor position (0 if none).
func (m *MemStore) DeviceCursor(account ids.AccountNumberHash, device ids.DeviceID) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v := m.vaults[account]
	if v == nil {
		return 0
	}
	return v.cursors[device]
}

// QuotaBytes returns the account's current deduplicated stored-ciphertext bytes.
func (m *MemStore) QuotaBytes(account ids.AccountNumberHash) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v := m.vaults[account]
	if v == nil {
		return 0
	}
	return v.quotaBytes
}

// SetTombstone records the (uuid, final_version, marker) triplet + the blob's
// current change-sequence (the position a device must ack past). Substrate only —
// it does not drop ciphertext (L2 reclaim is a separate step).
func (m *MemStore) SetTombstone(account ids.AccountNumberHash, blobID ids.BlobID, finalVersion Version) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.vault(account)
	seq := uint64(0)
	if e := v.blobs[blobID]; e != nil {
		seq = e.changeSeq
	}
	v.tombstones[blobID] = &tombstoneRec{finalVersion: finalVersion, changeSeq: seq}
	return nil
}

// Tombstone returns the recorded (final_version, marker) for a blob, if any.
func (m *MemStore) Tombstone(account ids.AccountNumberHash, blobID ids.BlobID) (Version, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v := m.vaults[account]
	if v == nil {
		return 0, false
	}
	rec, ok := v.tombstones[blobID]
	if !ok {
		return 0, false
	}
	return rec.finalVersion, true
}

// TombstoneRecord returns the full tombstone record for GC: final_version, the
// change-sequence a device must ack past, and whether L2 has reclaimed the body.
func (m *MemStore) TombstoneRecord(account ids.AccountNumberHash, blobID ids.BlobID) (finalVersion Version, changeSeq uint64, reclaimed bool, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v := m.vaults[account]
	if v == nil {
		return 0, 0, false, false
	}
	rec, found := v.tombstones[blobID]
	if !found {
		return 0, 0, false, false
	}
	return rec.finalVersion, rec.changeSeq, rec.reclaimed, true
}

// ListTombstones returns every blob id with a tombstone record (for the GC sweep).
func (m *MemStore) ListTombstones(account ids.AccountNumberHash) []ids.BlobID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v := m.vaults[account]
	if v == nil {
		return nil
	}
	out := make([]ids.BlobID, 0, len(v.tombstones))
	for id := range v.tombstones {
		out = append(out, id)
	}
	return out
}

// ReclaimTombstone is the Layer-2 storage reclamation: drop the ciphertext body
// but keep (uuid, final_version, marker). The server never learns "deleted"
// meaning (AS6); it only knows a uuid reached a final version. Adjusts quota down.
func (m *MemStore) ReclaimTombstone(account ids.AccountNumberHash, blobID ids.BlobID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.vaults[account]
	if v == nil {
		return ErrNotFound
	}
	rec, ok := v.tombstones[blobID]
	if !ok {
		return ErrNotFound
	}
	if e := v.blobs[blobID]; e != nil {
		v.quotaBytes -= uint64(len(e.ciphertext))
		e.ciphertext = nil
		e.size = 0
	}
	rec.reclaimed = true
	if rec.changeSeq > v.reclaimFloor {
		v.reclaimFloor = rec.changeSeq
	}
	return nil
}

// GCFloor returns the highest change-sequence whose tombstone has been L2-reclaimed.
// A pull with a non-zero cursor below this has missed reclaimed history and must
// full-reconcile (the server returns cursor-expired / 410).
func (m *MemStore) GCFloor(account ids.AccountNumberHash) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v := m.vaults[account]
	if v == nil {
		return 0
	}
	return v.reclaimFloor
}

// BlobVersion returns the current opaque version without fetching ciphertext.
func (m *MemStore) BlobVersion(account ids.AccountNumberHash, blobID ids.BlobID) (Version, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v := m.vaults[account]
	if v == nil {
		return 0, ErrNotFound
	}
	e := v.blobs[blobID]
	if e == nil {
		return 0, ErrNotFound
	}
	return e.version, nil
}

// GetHead returns the current opaque head record + its head_id, or ErrNotFound.
func (m *MemStore) GetHead(account ids.AccountNumberHash) ([]byte, [HeadIDLen]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var zero [HeadIDLen]byte
	v := m.vaults[account]
	if v == nil || !v.hasHead {
		return nil, zero, ErrNotFound
	}
	out := make([]byte, len(v.head))
	copy(out, v.head)
	return out, v.headID, nil
}

// AdvanceHead atomically CAS-advances the current-head pointer. prevHeadHash must
// equal the current head_id (or the zero hash for the genesis head). The record is
// stored opaquely; the new head_id = SHA-256(record).
func (m *MemStore) AdvanceHead(account ids.AccountNumberHash, prevHeadHash [HeadIDLen]byte, record []byte) ([HeadIDLen]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var zero [HeadIDLen]byte
	v := m.vault(account)

	if v.hasHead {
		if prevHeadHash != v.headID {
			return zero, ErrHeadCASMismatch
		}
	} else {
		// Genesis: the client must assert "no current head" via the zero hash.
		if prevHeadHash != genesisPrevHash {
			return zero, ErrHeadCASMismatch
		}
	}

	newID := headid.Compute(record)
	buf := make([]byte, len(record))
	copy(buf, record)
	v.head = buf
	v.headID = newID
	v.hasHead = true
	return newID, nil
}

// bytesEqual avoids a crypto/subtle import for a non-secret content comparison
// (this is opaque ciphertext equality for idempotency, not a MAC check).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// GetBlob returns the stored opaque ciphertext + version, or ErrNotFound.
func (m *MemStore) GetBlob(account ids.AccountNumberHash, blobID ids.BlobID) ([]byte, Version, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v := m.vaults[account]
	if v == nil {
		return nil, 0, ErrNotFound
	}
	e := v.blobs[blobID]
	if e == nil {
		return nil, 0, ErrNotFound
	}
	out := make([]byte, len(e.ciphertext))
	copy(out, e.ciphertext)
	return out, e.version, nil
}

// ListAccounts returns every account namespace present (for the GC scheduler,
// MYND-440). It is an enumeration of opaque account_number_hash keys — no IP, no
// content. Not part of BlobStore; the scheduler duck-types on it.
// DeleteAccount removes the account's entire in-memory vault namespace. Irreversible
// (MYND-506); idempotent on a missing account.
func (m *MemStore) DeleteAccount(account ids.AccountNumberHash) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.vaults, account)
	return nil
}

func (m *MemStore) ListAccounts() []ids.AccountNumberHash {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ids.AccountNumberHash, 0, len(m.vaults))
	for a := range m.vaults {
		out = append(out, a)
	}
	return out
}

// compile-time assertion that MemStore implements BlobStore.
var _ BlobStore = (*MemStore)(nil)

// SetMeta stores the opaque AEAD vault.meta blob for an account (MYND-425
// enrollment bootstrap). Called by an enrolled device's authed upload.
func (m *MemStore) SetMeta(account ids.AccountNumberHash, meta []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.vault(account)
	buf := make([]byte, len(meta))
	copy(buf, meta)
	v.meta = buf
}

// GetMeta returns the stored vault.meta blob, or ErrNotFound when the account has
// not uploaded one. Served pre-auth by account_number_hash so a new device can
// derive root_key before SCRAM-authenticating (the bytes are AEAD-protected).
func (m *MemStore) GetMeta(account ids.AccountNumberHash) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v := m.vaults[account]
	if v == nil || v.meta == nil {
		return nil, ErrNotFound
	}
	out := make([]byte, len(v.meta))
	copy(out, v.meta)
	return out, nil
}
