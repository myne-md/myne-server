// SPDX-License-Identifier: AGPL-3.0
// Vault discovery (myne-md/myne#911 task 7).
//
// The claim these tests pin is small and load-bearing: the answer is the
// caller's OWN bindings, read from the same table the sync surface authorizes
// against, and a caller with none gets an empty list rather than an error or
// somebody else's rows.
package authapi

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
)

func TestDiscoveryListsOnlyTheCallersBindings(t *testing.T) {
	reg := auth.NewRegistry()
	tokens := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, tokens)
	members := membership.New()

	var personA, personB ids.AccountNumberHash
	personA[0] = 0xa1
	personB[0] = 0xb2
	var vaultA, vaultB, vaultC ids.AccountNumberHash
	vaultA[0] = 0x01
	vaultB[0] = 0x02
	vaultC[0] = 0x03

	// A owns two vaults, B owns one. A must never see B's.
	if err := members.BindOwner(membership.VaultID(vaultA), membership.PersonID(personA)); err != nil {
		t.Fatal(err)
	}
	if err := members.BindMember(membership.VaultID(vaultB), membership.PersonID(personA)); err != nil {
		t.Fatal(err)
	}
	if err := members.BindOwner(membership.VaultID(vaultC), membership.PersonID(personB)); err != nil {
		t.Fatal(err)
	}

	var dev ids.DeviceID
	dev[0] = 0x07
	res, err := en.Enroll(personA, dev, auth.PathRecovery)
	if err != nil {
		t.Fatal(err)
	}

	h := New(reg, tokens)
	// The table this test populated IS the handler's table.
	h.members = members
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/b2b/vaults", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+hex.EncodeToString(res.Token[:]))
	got, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	if got.StatusCode != http.StatusOK {
		t.Fatalf("status %d", got.StatusCode)
	}
	var body struct {
		Vaults []vaultBindingWire `json:"vaults"`
	}
	if err := json.NewDecoder(got.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Vaults) != 2 {
		t.Fatalf("got %d vaults, want 2 (owner + member, never the other person's)", len(body.Vaults))
	}
	roles := map[string]string{}
	for _, v := range body.Vaults {
		roles[v.AccountHashHex] = v.Role
	}
	if roles[hex.EncodeToString(vaultA[:])] != "owner" {
		t.Fatalf("vault A role = %q, want owner", roles[hex.EncodeToString(vaultA[:])])
	}
	if roles[hex.EncodeToString(vaultB[:])] != "member" {
		t.Fatalf("vault B role = %q, want member", roles[hex.EncodeToString(vaultB[:])])
	}
	if _, ok := roles[hex.EncodeToString(vaultC[:])]; ok {
		t.Fatal("discovery leaked another person's vault")
	}
}

func TestDiscoveryRefusesAnUnauthenticatedCaller(t *testing.T) {
	h := New(auth.NewRegistry(), auth.NewTokenStore(auth.NewRegistry()))
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/b2b/vaults")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
}
