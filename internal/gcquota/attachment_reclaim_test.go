// SPDX-License-Identifier: AGPL-3.0

package gcquota

import (
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// A reclaimed ATTACHMENT tombstone record drops its stored body through the
// reclaim bridge — one horizon, one ack rule (MYND-468, "no parallel
// attachment-GC path"); a note record never fires the bridge, and
// ExtendedRetention suppresses both reclaims.
func TestHorizonGC_AttachmentBodyRidesRecordReclaim(t *testing.T) {
	st := store.NewMemStore()
	reg := auth.NewRegistry()

	ts := auth.NewTokenStore(reg)
	var account ids.AccountNumberHash
	account[0] = 0x42
	var device ids.DeviceID
	device[0] = 0x01
	enrollDev(t, reg, ts, account, device)

	fullIDHex := strings.Repeat("ee", 32)
	var attRecord ids.BlobID
	for i := range attRecord {
		attRecord[i] = 0xee
	}
	var noteRecord ids.BlobID
	noteRecord[0] = 0xaa
	var nonce [store.ContentNonceLen]byte

	// An attachment registration record (empty body) + its association, then a
	// tombstone; plus a tombstoned NOTE record for the negative case.
	if _, err := st.PushBlob(account, attRecord, 0, nonce, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBlobAttachmentID(account, attRecord, fullIDHex); err != nil {
		t.Fatal(err)
	}
	ver, err := st.PushBlob(account, attRecord, 1, [store.ContentNonceLen]byte{1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetTombstone(account, attRecord, ver); err != nil {
		t.Fatal(err)
	}
	nver, err := st.PushBlob(account, noteRecord, 0, nonce, []byte("note"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetTombstone(account, noteRecord, nver); err != nil {
		t.Fatal(err)
	}

	// The single active device acks past everything → both records reclaimable.
	st.AckCursor(account, device, 100)

	var reclaimedIDs []string
	gc := NewHorizonGC(st, reg, DefaultPolicy()).
		WithAttachmentReclaim(func(a ids.AccountNumberHash, attHex string) (uint64, bool) {
			if a != account {
				t.Fatalf("bridge account mismatch")
			}
			reclaimedIDs = append(reclaimedIDs, attHex)
			return 64, true
		})
	reclaimed, _ := gc.Run(account, 1)
	if reclaimed != 2 {
		t.Fatalf("reclaimed records = %d, want 2 (note + attachment)", reclaimed)
	}
	if len(reclaimedIDs) != 1 || reclaimedIDs[0] != fullIDHex {
		t.Fatalf("attachment bridge calls = %v, want exactly the attachment id", reclaimedIDs)
	}
}

func TestHorizonGC_ExtendedRetentionSkipsAttachmentBridge(t *testing.T) {
	st := store.NewMemStore()
	reg := auth.NewRegistry()

	ts := auth.NewTokenStore(reg)
	var account ids.AccountNumberHash
	account[0] = 0x43
	var device ids.DeviceID
	device[0] = 0x02
	enrollDev(t, reg, ts, account, device)
	var attRecord ids.BlobID
	attRecord[0] = 0xee
	var nonce [store.ContentNonceLen]byte
	if _, err := st.PushBlob(account, attRecord, 0, nonce, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBlobAttachmentID(account, attRecord, strings.Repeat("ee", 32)); err != nil {
		t.Fatal(err)
	}
	if err := st.SetTombstone(account, attRecord, 1); err != nil {
		t.Fatal(err)
	}
	st.AckCursor(account, device, 100)

	policy := DefaultPolicy()
	policy.ExtendedRetention = true
	bridgeFired := false
	gc := NewHorizonGC(st, reg, policy).
		WithAttachmentReclaim(func(ids.AccountNumberHash, string) (uint64, bool) {
			bridgeFired = true
			return 0, false
		})
	reclaimed, _ := gc.Run(account, 1)
	if reclaimed != 0 || bridgeFired {
		t.Fatalf("ExtendedRetention must suppress record AND body reclaim (reclaimed=%d, bridge=%v)", reclaimed, bridgeFired)
	}
}
