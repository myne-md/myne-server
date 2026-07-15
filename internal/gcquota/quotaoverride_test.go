// SPDX-License-Identifier: AGPL-3.0

package gcquota

import (
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

// TestQuotaGuard_Override: a per-account override wins over the global ceiling in
// both the sync-push (WouldExceedTotalForAccount) direction and via the effective
// resolver (MYND-506).
func TestQuotaGuard_Override(t *testing.T) {
	a1, a2 := acct(1), acct(2)
	// Global ceiling 1000; account 1 overridden down to 100, account 2 unset.
	qg := NewQuotaGuard(1000).WithOverride(func(a ids.AccountNumberHash, base uint64) uint64 {
		if a == a1 {
			return 100
		}
		return base
	})

	// Account 1: 150 bytes exceeds its 100 override even though it's under the global 1000.
	if !qg.WouldExceedTotalForAccount(a1, 0, 150) {
		t.Errorf("acct1: 150 bytes should exceed the 100 override")
	}
	if qg.WouldExceedTotalForAccount(a1, 0, 80) {
		t.Errorf("acct1: 80 bytes should be within the 100 override")
	}
	// Account 2: falls back to the global 1000.
	if qg.WouldExceedTotalForAccount(a2, 0, 150) {
		t.Errorf("acct2: 150 bytes should be within the global 1000")
	}
	if !qg.WouldExceedTotalForAccount(a2, 0, 1500) {
		t.Errorf("acct2: 1500 bytes should exceed the global 1000")
	}
}

// TestQuotaGuard_NoOverrideIsGlobal: with no override installed, the global ceiling
// applies (0 = unlimited).
func TestQuotaGuard_NoOverrideIsGlobal(t *testing.T) {
	if NewQuotaGuard(0).WouldExceedTotalForAccount(acct(1), 0, 1<<40) {
		t.Errorf("ceiling 0 should be unlimited")
	}
	if !NewQuotaGuard(10).WouldExceedTotalForAccount(acct(1), 0, 20) {
		t.Errorf("20 bytes should exceed the global ceiling 10")
	}
}
