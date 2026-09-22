// SPDX-License-Identifier: AGPL-3.0

package authapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The person-private profile plane (myne-md/myne#711 task 16): only a person
// BOUND to the vault may read or write a profile in it, the server records the
// writer, and a removal-scheduled delete touches only that writer's rows.
func TestProfile_OnlyABoundPersonCanReadWriteAndWriterIsRecorded(t *testing.T) {
	e := newB2BEnv(t)
	_, vaultTokA := e.account(t, b2bVaultA, 0x0b)
	_, _ = e.account(t, b2bOwner, 0x0a)
	_, memberAcctTok := e.account(t, b2bMember, 0x0d)
	_, otherAcctTok := e.account(t, b2bOther, 0x0e)

	// Owner registers (vault device session), then binds the member.
	_, ownerA := e.bind(t, b2bVaultA, vaultTokA, b2bOwner, "owner")
	if resp, _ := e.bind(t, b2bVaultA, ownerA.TokenHex, b2bMember, "member"); resp.StatusCode != http.StatusOK {
		t.Fatalf("owner binding the member: want 200, got %d", resp.StatusCode)
	}

	profileID := strings.Repeat("e1", 16)
	url := e.srv.URL + "/b2b/vaults/" + b2bVaultA + "/profiles/" + profileID

	// A bound person writes and reads back their own profile.
	resp, _ := sendJSON(t, http.MethodPut, url, memberAcctTok, "sealed-profile-bytes")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bound person PUT: want 200, got %d", resp.StatusCode)
	}
	resp, body := sendJSON(t, http.MethodGet, url, memberAcctTok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bound person GET: want 200, got %d", resp.StatusCode)
	}
	var got string
	if err := json.Unmarshal(body, &got); err != nil || got != "sealed-profile-bytes" {
		t.Fatalf("profile round-trip: got %q (%v)", body, err)
	}

	// A person NOT bound to the vault cannot write or read it.
	if resp, _ := sendJSON(t, http.MethodPut, url, otherAcctTok, "x"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unbound PUT: want 403, got %d", resp.StatusCode)
	}
	if resp, _ := sendJSON(t, http.MethodGet, url, otherAcctTok, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unbound GET: want 403, got %d", resp.StatusCode)
	}
	// An unknown profile is 404 for a bound person.
	missing := e.srv.URL + "/b2b/vaults/" + b2bVaultA + "/profiles/" + strings.Repeat("ff", 16)
	if resp, _ := sendJSON(t, http.MethodGet, missing, memberAcctTok, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown profile GET: want 404, got %d", resp.StatusCode)
	}

	// The store recorded the member as the writer, and a scheduled delete for
	// that person removes their row (and only theirs).
	if n := e.h.Profiles().DeleteByPerson(acct(t, b2bVaultA), b2bPersonID(t, b2bMember)); n != 1 {
		t.Fatalf("DeleteByPerson: want 1 removed, got %d", n)
	}
	if resp, _ := sendJSON(t, http.MethodGet, url, memberAcctTok, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("profile after scheduled delete: want 404, got %d", resp.StatusCode)
	}
	// No other person's rows were touched (none existed, but the delete must not
	// error or over-remove).
	if n := e.h.Profiles().DeleteByPerson(acct(t, b2bVaultA), b2bPersonID(t, b2bMember)); n != 0 {
		t.Fatalf("second DeleteByPerson: want 0, got %d", n)
	}
}

// Removal schedules the person's profiles for reclamation after the grace: the
// profile survives until the sweep passes the due time, then is gone.
func TestProfile_RemovalSchedulesDeletionAfterTheGrace(t *testing.T) {
	e := newB2BEnv(t)
	e.h.WithProfileDeleteGrace(time.Hour)
	_, vaultTokA := e.account(t, b2bVaultA, 0x0b)
	_, _ = e.account(t, b2bOwner, 0x0a)
	_, memberAcctTok := e.account(t, b2bMember, 0x0d)
	_, ownerA := e.bind(t, b2bVaultA, vaultTokA, b2bOwner, "owner")
	if resp, _ := e.bind(t, b2bVaultA, ownerA.TokenHex, b2bMember, "member"); resp.StatusCode != http.StatusOK {
		t.Fatalf("bind member: want 200, got %d", resp.StatusCode)
	}
	profileID := strings.Repeat("e1", 16)
	url := e.srv.URL + "/b2b/vaults/" + b2bVaultA + "/profiles/" + profileID
	if resp, _ := sendJSON(t, http.MethodPut, url, memberAcctTok, "sealed"); resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT: want 200, got %d", resp.StatusCode)
	}

	// Remove the member (owner token): the profile is scheduled, not deleted.
	if resp := e.remove(t, b2bVaultA, ownerA.TokenHex, b2bMember); resp.StatusCode != http.StatusOK {
		t.Fatalf("remove: want 200, got %d", resp.StatusCode)
	}
	if resp, _ := sendJSON(t, http.MethodGet, url, memberAcctTok, nil); resp.StatusCode == http.StatusOK {
		t.Fatalf("the removed member's token should no longer read the profile")
	}
	vault := acct(t, b2bVaultA)
	person := b2bPersonID(t, b2bMember)
	pid, ok := parseProfileID(profileID)
	if !ok {
		t.Fatal("bad profile id")
	}
	if _, ok := e.h.Profiles().Get(vault, pid); !ok {
		t.Fatalf("the profile must survive until the grace passes")
	}
	// A sweep before the due time reclaims nothing; after it, it reclaims the row.
	if n := e.h.Profiles().SweepDue(time.Now().Add(30 * time.Minute)); n != 0 {
		t.Fatalf("sweep before the grace: want 0, got %d", n)
	}
	if n := e.h.Profiles().SweepDue(time.Now().Add(2 * time.Hour)); n != 1 {
		t.Fatalf("sweep after the grace: want 1, got %d", n)
	}
	if _, ok := e.h.Profiles().Get(vault, pid); ok {
		t.Fatalf("the profile must be reclaimed after the grace")
	}
	_ = person
}
