// SPDX-License-Identifier: AGPL-3.0

package syncapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/authapi"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// The membership seam has a FAKE in every other test in this package, and the
// fake is why this bug shipped: it answers `DeviceActive` without ever looking an
// account up, so "the token names a device" and "the registry knows that device"
// are the same statement there and could not be told apart. This file drives the
// REAL `authapi.Handler` as the seam — real registry, real membership table, real
// per-vault token store — because the defect lives exactly in the join between
// them.
//
// # The failure this pins
//
// `vaultMetaWriteAccount` authorizes a `vault.meta` PUT on a namespace that has an
// owner by resolving the caller's PER-VAULT token and asking whether the device it
// was issued to is still active. That question went to
// `auth.Registry.Get(person, device)` — but the registry is keyed by the SCRAM
// account the device is registered under, and a shared vault's owner binding is
// minted by the VAULT's own device session, so the account is the vault's account
// number while `binding.Person` is the owner's person id. The lookup could only
// miss, and every owner `vault.meta` write (a rotation's meta publish, which is
// the first thing a rotation delivery does) answered `401 device_revoked` for a
// device nobody had revoked. Client-side this surfaced as two red sim tests three
// repositories away, in myne-md/myne's `sync-sim` gate.
//
// `binding.Account` now carries the account the token was issued under, so the
// check asks about a key the registry actually holds.

// realDepsHarness wires the real auth surface as the sync surface's membership
// seam, which is what production composes.
type realDepsHarness struct {
	syncSrv  *httptest.Server
	authSrv  *httptest.Server
	reg      *auth.Registry
	ah       *authapi.Handler
	vault    ids.AccountNumberHash
	ownerDev ids.DeviceID
	// vaultToken authenticates the vault's own device session; ownerToken is the
	// per-vault membership token minted for the owner person.
	vaultToken string
	ownerToken string
}

const ownerPersonHex = "11111111111111111111111111111111"

func newRealDepsHarness(t *testing.T) *realDepsHarness {
	t.Helper()
	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)

	var vault ids.AccountNumberHash
	vault[0] = 0x42
	var dev ids.DeviceID
	dev[0] = 0x01
	res, err := en.Enroll(vault, dev, auth.PathPassword)
	if err != nil {
		t.Fatalf("enroll the vault's own device: %v", err)
	}

	ah := authapi.New(reg, ts)
	authMux := http.NewServeMux()
	ah.Register(authMux)
	authSrv := httptest.NewServer(authMux)
	t.Cleanup(authSrv.Close)

	syncMux := http.NewServeMux()
	New(st, ts).WithMembership(ah).Register(syncMux)
	syncSrv := httptest.NewServer(syncMux)
	t.Cleanup(syncSrv.Close)

	h := &realDepsHarness{
		syncSrv:    syncSrv,
		authSrv:    authSrv,
		reg:        reg,
		ah:         ah,
		vault:      vault,
		ownerDev:   dev,
		vaultToken: hex.EncodeToString(res.Token),
	}
	h.ownerToken = h.bindOwner(t)
	return h
}

// bindOwner posts the REAL members route with the vault's own device session, the
// shape every pre-B2B vault's owner binding is minted in, and returns the per-vault
// token the route issued.
func (h *realDepsHarness) bindOwner(t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"person_id_hex": ownerPersonHex,
		"role":          "owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost,
		h.authSrv.URL+"/b2b/vaults/"+hex.EncodeToString(h.vault[:])+"/members",
		bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.vaultToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("bind owner: %d %s", res.StatusCode, raw)
	}
	var out struct {
		TokenHex string `json:"token_hex"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("bind owner response: %v", err)
	}
	if out.TokenHex == "" {
		t.Fatal("bind owner issued no token")
	}
	return out.TokenHex
}

// putMeta writes the vault.meta blob as the owner's per-vault token, which is what
// a rotation delivery does first.
func (h *realDepsHarness) putMeta() (int, string) {
	req, err := http.NewRequest(http.MethodPut, h.syncSrv.URL+"/vault.meta",
		strings.NewReader("opaque-vault-meta-ciphertext"))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.ownerToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(raw)
}

// The owner's per-vault token must publish `vault.meta` for a vault it owns, and
// the SAME token must stop working the moment the device it was issued to is
// retired: both arms are one check, and the check is the one that was asking the
// wrong key.
func TestOwnerPerVaultTokenPublishesMetaAndDiesWithItsDevice(t *testing.T) {
	h := newRealDepsHarness(t)

	if status, body := h.putMeta(); status != http.StatusOK {
		t.Fatalf("the owner's per-vault token must publish vault.meta, got %d %s", status, body)
	}

	if err := h.reg.Retire(h.vault, h.ownerDev); err != nil {
		t.Fatalf("retire the owner device: %v", err)
	}
	status, body := h.putMeta()
	if status != http.StatusUnauthorized {
		t.Fatalf("a retired device must stop publishing, got %d %s", status, body)
	}
	if !strings.Contains(body, "device_revoked") {
		t.Fatalf("the refusal must name the revocation, got %s", body)
	}
}

// The binding the real route mints must carry the account the registry is keyed
// by. Asserted separately from the route above so a failure says WHICH half broke:
// an unattributed token is skipped by the device check (it cannot be guessed at),
// so without this the publish would go green while revocation silently stopped
// enforcing.
func TestTheIssuedOwnerTokenCarriesItsIssuingAccount(t *testing.T) {
	h := newRealDepsHarness(t)

	b, ok := h.ah.ResolveMember(h.ownerToken)
	if !ok {
		t.Fatal("the owner's per-vault token does not resolve")
	}
	if b.Account != h.vault {
		t.Fatalf("the token's issuing account is %x, want the vault account %x",
			b.Account, h.vault)
	}
	if b.Device != h.ownerDev {
		t.Fatalf("the token's device is %x, want %x", b.Device, h.ownerDev)
	}
	if b.Account == ids.AccountNumberHash(b.Person) {
		t.Fatal("the issuing account and the person id must not be interchangeable: " +
			"that conflation is the defect this pins")
	}
}
