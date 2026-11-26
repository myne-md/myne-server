// SPDX-License-Identifier: AGPL-3.0-only

package syncapi

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

func TestAccountStatus_TokenDerivedNoURLIdentifier(t *testing.T) {
	var calledWith ids.AccountNumberHash
	status := func(scope StatusScope) any {
		calledWith = scope.Account
		return map[string]string{"account": hex.EncodeToString(scope.Account[:])}
	}

	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)
	var a ids.AccountNumberHash
	a[0] = 0x42
	var d ids.DeviceID
	d[0] = 0x01
	res, err := en.Enroll(a, d, auth.PathPassword)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(st, ts).WithAccountStatus(status).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	token := hex.EncodeToString(res.Token)

	// Authed → 200, and the account is the TOKEN's account even though the query
	// carries a DIFFERENT account value (it must be ignored — no URL/query selector).
	resp, _ := do(t, srv, http.MethodGet, "/account/status?account=deadbeefdeadbeefdeadbeefdeadbeef", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authed status → %d, want 200", resp.StatusCode)
	}
	if calledWith != a {
		t.Errorf("account was not token-derived: called with %x, want %x (URL/query honored?)", calledWith, a)
	}

	// Unauthenticated → 401.
	if resp2, _ := do(t, srv, http.MethodGet, "/account/status", "", ""); resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthed status → %d, want 401", resp2.StatusCode)
	}
}

// A person session's status scope carries the vaults it owns, so the projection
// can report ONE figure for the account (myne-md/myne#911 task 11).
//
// Two claims, and the second is the one that keeps a vault's own figure honest:
// an account with an owner binding is a person and gets its owned vaults; an
// account with none is a vault session and gets an empty scope, so the same
// route serves both without a second identity flag on the wire.
func TestAccountStatus_PersonScopeCarriesTheOwnedVaults(t *testing.T) {
	var got StatusScope
	status := func(scope StatusScope) any {
		got = scope
		return map[string]bool{}
	}

	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)

	// A person account, plus two vaults it owns and one it merely joined.
	var person ids.AccountNumberHash
	person[0] = 0x11
	var ownedA, ownedB, joined ids.AccountNumberHash
	ownedA[0], ownedB[0], joined[0] = 0x21, 0x22, 0x23
	var d ids.DeviceID
	d[0] = 0x01
	res, err := en.Enroll(person, d, auth.PathPassword)
	if err != nil {
		t.Fatal(err)
	}

	fm := &fakeMembership{
		bindings: map[ids.AccountNumberHash]map[ids.AccountNumberHash]string{
			ownedA: {person: "owner"},
			ownedB: {person: "owner"},
			joined: {person: "member"},
		},
	}
	mux := http.NewServeMux()
	New(st, ts).WithMembership(fm).WithAccountStatus(status).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, _ := do(t, srv, http.MethodGet, "/account/status", hex.EncodeToString(res.Token), "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("person status → %d, want 200", resp.StatusCode)
	}
	if !got.Person {
		t.Error("a person session must be reported as a person")
	}
	if got.Account != person {
		t.Errorf("scope account = %x, want the token's %x", got.Account, person)
	}
	if len(got.Vaults) != 2 {
		t.Fatalf("owned vaults = %d, want 2 (the member vault is not the person's usage)", len(got.Vaults))
	}
	for _, v := range got.Vaults {
		if v == joined {
			t.Error("a vault the person merely JOINED must not count toward their usage")
		}
	}

	// The same route for a vault's own device token: no bindings, so the scope is
	// a vault scope and the projection reports that vault's own figure.
	var vaultAccount ids.AccountNumberHash
	vaultAccount[0] = 0x31
	vres, err := en.Enroll(vaultAccount, d, auth.PathPassword)
	if err != nil {
		t.Fatal(err)
	}
	got = StatusScope{}
	resp2, _ := do(t, srv, http.MethodGet, "/account/status", hex.EncodeToString(vres.Token), "")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("vault status → %d, want 200", resp2.StatusCode)
	}
	if got.Person || len(got.Vaults) != 0 {
		t.Errorf("a vault session must not be reported as a person: %+v", got)
	}
	if got.Account != vaultAccount {
		t.Errorf("scope account = %x, want %x", got.Account, vaultAccount)
	}
}
