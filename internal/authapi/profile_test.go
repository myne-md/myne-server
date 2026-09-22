// SPDX-License-Identifier: AGPL-3.0

package authapi

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/myne-md/myne-server/internal/profiles"
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

	pidBytes := profiles.DeriveProfileID(acct(t, b2bVaultA), b2bPersonID(t, b2bMember))
	profileID := hex.EncodeToString(pidBytes[:])
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
	// An id that is NOT the caller's own is refused with 403 (not 404): the
	// server recomputes the id from the session person and never confirms
	// whether some other profile exists.
	foreign := e.srv.URL + "/b2b/vaults/" + b2bVaultA + "/profiles/" + strings.Repeat("ff", 16)
	if resp, _ := sendJSON(t, http.MethodGet, foreign, memberAcctTok, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign profile GET: want 403, got %d", resp.StatusCode)
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

// A bound member may only address their OWN profile id. The id is a pure
// function of (person, vault) and a peer's person_id_hash is visible in the
// roster, so without the server-side recompute one member could read or
// overwrite another's private AI profile.
func TestProfile_ABoundMemberCannotAddressAnotherMembersProfile(t *testing.T) {
	e := newB2BEnv(t)
	_, vaultTokA := e.account(t, b2bVaultA, 0x0b)
	_, _ = e.account(t, b2bOwner, 0x0a)
	_, memberAcctTok := e.account(t, b2bMember, 0x0d)
	_, otherAcctTok := e.account(t, b2bOther, 0x0e)

	_, ownerA := e.bind(t, b2bVaultA, vaultTokA, b2bOwner, "owner")
	if resp, _ := e.bind(t, b2bVaultA, ownerA.TokenHex, b2bMember, "member"); resp.StatusCode != http.StatusOK {
		t.Fatalf("owner binding the member: want 200, got %d", resp.StatusCode)
	}
	if resp, _ := e.bind(t, b2bVaultA, ownerA.TokenHex, b2bOther, "member"); resp.StatusCode != http.StatusOK {
		t.Fatalf("owner binding the other: want 200, got %d", resp.StatusCode)
	}

	// The OTHER member's id, computed the way any bound peer could.
	otherIDBytes := profiles.DeriveProfileID(acct(t, b2bVaultA), b2bPersonID(t, b2bOther))
	otherID := hex.EncodeToString(otherIDBytes[:])
	otherURL := e.srv.URL + "/b2b/vaults/" + b2bVaultA + "/profiles/" + otherID

	// Seed a real row for the other member (as that member), so the refusal is
	// proven against a profile that EXISTS, not a 404 from emptiness.
	if resp, _ := sendJSON(t, http.MethodPut, otherURL, otherAcctTok, "other-secret"); resp.StatusCode != http.StatusOK {
		t.Fatalf("other member PUT own profile: want 200, got %d", resp.StatusCode)
	}

	// The member's own token against the OTHER member's id must be refused, and
	// it must be a 403 (not a 404 that would still confirm existence).
	if resp, _ := sendJSON(t, http.MethodGet, otherURL, memberAcctTok, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-member GET: want 403, got %d", resp.StatusCode)
	}
	if resp, _ := sendJSON(t, http.MethodPut, otherURL, memberAcctTok, "clobber"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-member PUT: want 403, got %d", resp.StatusCode)
	}

	// The other member's row is untouched.
	if resp, body := sendJSON(t, http.MethodGet, otherURL, otherAcctTok, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("other member GET own profile: want 200, got %d", resp.StatusCode)
	} else {
		var got string
		if err := json.Unmarshal(body, &got); err != nil || got != "other-secret" {
			t.Fatalf("other member's profile survived a cross-member PUT: got %q (%v)", body, err)
		}
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
	pidBytes := profiles.DeriveProfileID(acct(t, b2bVaultA), b2bPersonID(t, b2bMember))
	profileID := hex.EncodeToString(pidBytes[:])
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
