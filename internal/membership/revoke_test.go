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
	tokA, err := ts.Issue(person, vault)
	if err != nil {
		t.Fatalf("Issue A: %v", err)
	}
	tokB, err := ts.Issue(other, vault)
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
