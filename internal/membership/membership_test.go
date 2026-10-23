// SPDX-License-Identifier: AGPL-3.0

package membership

import (
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func person(b byte) PersonID {
	var p PersonID
	p[0] = b
	return p
}

func vault(b byte) VaultID {
	var v VaultID
	v[0] = b
	return v
}

// account is the SCRAM account a token is issued under: the account the issuing
// device is registered with, which is what the revocation check asks the device
// registry about. It is not the person holding the binding.
func account(b byte) ids.AccountNumberHash {
	var a ids.AccountNumberHash
	a[0] = b
	return a
}

func TestOwnerIsSingleton(t *testing.T) {
	tbl := New()
	v := vault(1)
	owner := person(0xAA)

	if err := tbl.BindOwner(v, owner); err != nil {
		t.Fatalf("BindOwner: %v", err)
	}
	if role, ok := tbl.Role(v, owner); !ok || role != RoleOwner {
		t.Fatalf("role = %v ok=%v, want owner", role, ok)
	}
	got, ok := tbl.OwnerOf(v)
	if !ok || got.Person != owner {
		t.Fatalf("OwnerOf = %+v ok=%v, want the bound owner", got, ok)
	}
	// Re-binding the SAME owner is idempotent.
	if err := tbl.BindOwner(v, owner); err != nil {
		t.Fatalf("re-BindOwner same person: %v", err)
	}
	// A DIFFERENT person cannot be a second owner.
	if err := tbl.BindOwner(v, person(0xBB)); err != ErrOwnerExists {
		t.Fatalf("second owner err = %v, want ErrOwnerExists", err)
	}
}

func TestBindMemberAndRemove(t *testing.T) {
	tbl := New()
	v := vault(2)
	owner := person(0xAA)
	member := person(0xBB)

	if err := tbl.BindOwner(v, owner); err != nil {
		t.Fatalf("BindOwner: %v", err)
	}
	if err := tbl.BindMember(v, member); err != nil {
		t.Fatalf("BindMember: %v", err)
	}
	if err := tbl.BindMember(v, member); err != ErrAlreadyBound {
		t.Fatalf("duplicate BindMember err = %v, want ErrAlreadyBound", err)
	}
	if role, ok := tbl.Role(v, member); !ok || role != RoleMember {
		t.Fatalf("member role = %v ok=%v, want member", role, ok)
	}

	// Owner first, then member.
	members := tbl.Members(v)
	if len(members) != 2 || members[0].Role != RoleOwner || members[1].Person != member {
		t.Fatalf("Members = %+v, want owner first then member", members)
	}

	// A member can be removed; the owner cannot.
	if err := tbl.Remove(v, member); err != nil {
		t.Fatalf("Remove member: %v", err)
	}
	if _, ok := tbl.Role(v, member); ok {
		t.Fatalf("member still bound after Remove")
	}
	if err := tbl.Remove(v, owner); err != ErrOwnerNotFound {
		t.Fatalf("Remove owner err = %v, want ErrOwnerNotFound", err)
	}
	if err := tbl.Remove(v, member); err != ErrNotBound {
		t.Fatalf("Remove unbound err = %v, want ErrNotBound", err)
	}
}

func TestPersonSpansVaults(t *testing.T) {
	tbl := New()
	p := person(0xCC)
	if err := tbl.BindOwner(vault(1), p); err != nil {
		t.Fatal(err)
	}
	if err := tbl.BindMember(vault(2), p); err != nil {
		t.Fatal(err)
	}
	if got := tbl.Vaults(p); len(got) != 2 {
		t.Fatalf("Vaults = %+v, want 2 bindings", got)
	}
	// A person bound in one vault is unbound in another.
	if _, ok := tbl.Role(vault(3), p); ok {
		t.Fatalf("person reported bound in an unrelated vault")
	}
}

func TestTokenGrantAndTargetedRevoke(t *testing.T) {
	tbl := New()
	store := NewTokenStore(tbl)
	v := vault(9)
	owner := person(0xAA)
	member := person(0xBB)

	if err := tbl.BindOwner(v, owner); err != nil {
		t.Fatal(err)
	}
	if err := tbl.BindMember(v, member); err != nil {
		t.Fatal(err)
	}

	// A token can be minted only for an existing binding.
	if _, err := store.Issue(person(0xDD), v, DeviceID{0x0a}, account(0xaa)); err != ErrNotBound {
		t.Fatalf("Issue for unbound person err = %v, want ErrNotBound", err)
	}
	tok, err := store.Issue(member, v, DeviceID{0x0a}, account(0xaa))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if b, err := store.Resolve(tok); err != nil || b.Person != member || b.Vault != v {
		t.Fatalf("Resolve = %+v err=%v, want the member binding", b, err)
	}

	// Revoking the member's binding across one vault drops their token...
	store.Revoke(v, member)
	if _, err := store.Resolve(tok); err != ErrUnauthenticated {
		t.Fatalf("Resolve after Revoke err = %v, want ErrUnauthenticated", err)
	}
	// ...and a token for another vault is unaffected.
	other := vault(10)
	if err := tbl.BindMember(other, member); err != nil {
		t.Fatal(err)
	}
	otherTok, err := store.Issue(member, other, DeviceID{0x0a}, account(0xaa))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(otherTok); err != nil {
		t.Fatalf("other vault token refused after a targeted revoke: %v", err)
	}
}
