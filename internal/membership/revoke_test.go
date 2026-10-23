// SPDX-License-Identifier: AGPL-3.0

package membership

import (
	"encoding/hex"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func TestRevokeReportsRevokedTokensToObserver(t *testing.T) {
	tbl := New()
	vault := ids.AccountNumberHash{1}
	person := PersonID{2}
	other := PersonID{3}
	if err := tbl.BindOwner(vault, PersonID{9}); err != nil {
		t.Fatalf("BindOwner: %v", err)
	}
	if err := tbl.BindMember(vault, person); err != nil {
		t.Fatalf("BindMember: %v", err)
	}
	if err := tbl.BindMember(vault, other); err != nil {
		t.Fatalf("BindMember other: %v", err)
	}
	ts := NewTokenStore(tbl)
	tokA, err := ts.Issue(person, vault, DeviceID{0x0a}, account(0xaa))
	if err != nil {
		t.Fatalf("Issue A: %v", err)
	}
	tokB, err := ts.Issue(other, vault, DeviceID{0x0b}, account(0xaa))
	if err != nil {
		t.Fatalf("Issue B: %v", err)
	}

	var revoked []string
	ts.SetOnRevoke(func(h string) { revoked = append(revoked, h) })
	ts.Revoke(vault, person)

	if len(revoked) != 1 || revoked[0] != hex.EncodeToString(tokA) {
		t.Fatalf("Revoke must report exactly the removed person's token, got %v", revoked)
	}
	// Another person's token in the same vault is untouched.
	if _, err := ts.Resolve(tokB); err != nil {
		t.Fatal("another person's token must survive the removal")
	}
	if _, err := ts.Resolve(tokA); err == nil {
		t.Fatal("the removed token must be refused")
	}
}

// The device a token was issued to survives a restart (myne-md/myne#911 task 9).
//
// Revocation's coverage of a shared vault depends on the token naming its
// device, and that attribution is only as good as persistence: a snapshot that
// dropped the field would make every restored token unattributable, so a revoked
// device would sync every shared vault again after the server restarted, with
// nothing failing at the time it was written.
func TestDeviceAttributionSurvivesSnapshotAndLoad(t *testing.T) {
	table := New()
	var person PersonID
	person[0] = 0x11
	var vault VaultID
	vault[0] = 0x22
	if err := table.BindOwner(vault, PersonID{0x09}); err != nil {
		t.Fatal(err)
	}
	if err := table.BindMember(vault, person); err != nil {
		t.Fatal(err)
	}
	store := NewTokenStore(table)
	var device DeviceID
	device[0] = 0x0a
	if _, err := store.Issue(person, vault, device, account(0xaa)); err != nil {
		t.Fatal(err)
	}
	rows := store.Snapshot()
	if len(rows) != 1 {
		t.Fatalf("want one row, got %d", len(rows))
	}

	restored := NewTokenStore(table)
	if err := restored.Load(rows); err != nil {
		t.Fatal(err)
	}
	b, err := restored.Resolve(ids.DeviceToken(rows[0].Token))
	if err != nil {
		t.Fatal(err)
	}
	if b.Device != device {
		t.Fatalf("device attribution lost across a restart: got %x want %x", b.Device[:], device[:])
	}

	// A row written before the field existed carries no device and loads as
	// unattributable rather than failing the whole load.
	rows[0].Device = nil
	legacy := NewTokenStore(table)
	if err := legacy.Load(rows); err != nil {
		t.Fatalf("a legacy row must still load: %v", err)
	}
	b, err = legacy.Resolve(ids.DeviceToken(rows[0].Token))
	if err != nil {
		t.Fatal(err)
	}
	if b.Device != (DeviceID{}) {
		t.Fatalf("a legacy row must load as unattributable, got %x", b.Device[:])
	}
}
