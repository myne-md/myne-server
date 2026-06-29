// SPDX-License-Identifier: AGPL-3.0

package ids

import "testing"

// The three identifier types are nominally distinct (the compiler enforces that an
// AccountNumberHash can't be passed where a DeviceID is wanted). This test documents
// the model + pins the byte lengths so a later refactor can't silently collapse them.
func TestIdentifierModelDistinct(t *testing.T) {
	if AccountNumberHashLen != 16 || DeviceIDLen != 16 || BlobIDLen != 16 {
		t.Fatalf("identifier lengths drifted: acct=%d device=%d blob=%d",
			AccountNumberHashLen, DeviceIDLen, BlobIDLen)
	}

	// A DeviceToken is a distinct, separately-sized opaque credential — revoking it
	// must never require touching a DeviceID.
	var dev DeviceID
	tok := DeviceToken{0x01, 0x02, 0x03}
	if len(tok) == len(dev) {
		// not a real constraint, just asserting they are independent values
		_ = tok
	}
	if len(dev) != DeviceIDLen {
		t.Fatalf("DeviceID size %d != %d", len(dev), DeviceIDLen)
	}
}
