// SPDX-License-Identifier: AGPL-3.0-only

package httpapi

import (
	"testing"

	"github.com/myne-md/myne-server/internal/accounts"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/syncapi"
)

// The one arithmetic claim this feature makes: an account's usage is the SUM of
// the vaults it owns, not one of them and not the person's own namespace
// (myne-md/myne#911 task 11).
//
// Extracted as a function precisely so this is testable without a server: the
// alternative was asserting it through a full HTTP round trip, which would have
// tested the wiring and left the addition itself unmeasured.
func TestAggregateStoredBytes_SumsTheOwnedVaults(t *testing.T) {
	var a, b, c ids.AccountNumberHash
	a[0], b[0], c[0] = 0x01, 0x02, 0x03

	perVault := map[ids.AccountNumberHash]uint64{a: 100, b: 250, c: 7}
	usedBytes := func(h ids.AccountNumberHash) uint64 { return perVault[h] }

	// Two owned vaults: the total, not either one.
	if got := aggregateStoredBytes(usedBytes, []ids.AccountNumberHash{a, b}); got != 350 {
		t.Errorf("aggregate = %d, want 350 (100 + 250)", got)
	}
	// A single vault still reports that vault, so the aggregate cannot be
	// distinguished from a per-vault figure by arithmetic alone (it is the
	// `person` bit that tells the client which it is).
	if got := aggregateStoredBytes(usedBytes, []ids.AccountNumberHash{c}); got != 7 {
		t.Errorf("single-vault aggregate = %d, want 7", got)
	}
	// A person who owns nothing: zero, never an error and never the person's own
	// namespace read.
	if got := aggregateStoredBytes(usedBytes, nil); got != 0 {
		t.Errorf("empty aggregate = %d, want 0", got)
	}
	// A vault the person does NOT own is not in the list the caller passes, and
	// this function has no way to add one: the filtering is the membership seam's
	// job (`OwnedVaults`), which is why this test does not pretend to cover it.
}

// The projection's choice of KEY, which is what this feature is about: a person
// scope reports the account total and the PERSON's effective ceiling, a vault
// scope reports that vault's own figure and the vault's own ceiling
// (myne-md/myne#911 task 11).
//
// The two rows are given deliberately different overrides, so a projection that
// read the wrong one cannot pass by accident: the person's is 5 GiB and the
// vault's is 2 GiB.
func TestAccountStatusFor_PersonScopeSumsOwnedVaultsAndReadsThePersonCeiling(t *testing.T) {
	var person, vaultA, vaultB, otherVault ids.AccountNumberHash
	person[0], vaultA[0], vaultB[0], otherVault[0] = 0x11, 0x21, 0x22, 0x31

	const gib = 1024 * 1024 * 1024
	perAccount := map[ids.AccountNumberHash]uint64{
		person:     0, // a person's own namespace holds no blobs
		vaultA:     3 * gib,
		vaultB:     2 * gib,
		otherVault: 7 * gib, // not owned: must not be counted
	}
	usedBytes := func(h ids.AccountNumberHash) uint64 { return perAccount[h] }
	deviceCount := func(ids.AccountNumberHash) uint64 { return 2 }

	acct := accounts.New(t.TempDir() + "/accounts.json")
	acct.Update(person, func(p *accounts.Policy) { p.QuotaOverrideBytes = 5 * gib })
	acct.Update(vaultA, func(p *accounts.Policy) { p.QuotaOverrideBytes = 2 * gib })

	personView := accountStatusFor(
		syncapi.StatusScope{Account: person, Person: true, Vaults: []ids.AccountNumberHash{vaultA, vaultB}},
		usedBytes, deviceCount, acct, 0, 0,
	)
	if !personView.Person {
		t.Error("person scope must be reported as a person")
	}
	if personView.StoredBytes != 5*gib {
		t.Errorf("stored_bytes = %d, want %d (3 GiB + 2 GiB, the owned vaults only)", personView.StoredBytes, 5*gib)
	}
	if personView.VaultCount != 2 {
		t.Errorf("vault_count = %d, want 2", personView.VaultCount)
	}
	if personView.QuotaBytes != 5*gib {
		t.Errorf("quota_bytes = %d, want the PERSON's %d override", personView.QuotaBytes, 5*gib)
	}

	// The same store, asked about a vault: that vault's own figure and ceiling,
	// which is what a legacy account keeps.
	vaultView := accountStatusFor(
		syncapi.StatusScope{Account: vaultA}, usedBytes, deviceCount, acct, 0, 0,
	)
	if vaultView.Person || vaultView.VaultCount != 0 {
		t.Errorf("vault scope must not be reported as a person: %+v", vaultView)
	}
	if vaultView.StoredBytes != 3*gib {
		t.Errorf("vault stored_bytes = %d, want %d", vaultView.StoredBytes, 3*gib)
	}
	if vaultView.QuotaBytes != 2*gib {
		t.Errorf("vault quota_bytes = %d, want that VAULT's %d override", vaultView.QuotaBytes, 2*gib)
	}
}
