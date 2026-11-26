// SPDX-License-Identifier: AGPL-3.0-only

package authapi

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
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
	"github.com/myne-md/myne-server/internal/store"
)

// Fixed 16-byte ids, hex-encoded. Two vaults and two people is the smallest
// shape that can express "revoking one binding does not touch the person's other
// vaults".
var (
	b2bVaultA  = strings.Repeat("aa", 16)
	b2bVaultB  = strings.Repeat("bb", 16)
	b2bOwner   = strings.Repeat("11", 16)
	b2bMember  = strings.Repeat("22", 16)
	b2bOther   = strings.Repeat("33", 16)
	b2bAnybody = strings.Repeat("44", 16)
)

type b2bEnv struct {
	srv *httptest.Server
	h   *Handler
}

func newB2BEnv(t *testing.T) *b2bEnv {
	t.Helper()
	reg := auth.NewRegistry()
	tokens := auth.NewTokenStore(reg)
	h := New(reg, tokens)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &b2bEnv{srv: srv, h: h}
}

// account registers a SCRAM verifier for idHex and returns the client plus the
// first device's bearer token. A person account and a vault account are the SAME
// thing here: both are 16-byte ids in the /auth namespace (see b2b.go's header).
func (e *b2bEnv) account(t *testing.T, idHex string, secretByte byte) (*testClient, string) {
	t.Helper()
	c := &testClient{
		srv:      e.srv,
		username: idHex,
		account:  idHex,
		secret:   bytes.Repeat([]byte{secretByte}, 32),
		salt:     bytes.Repeat([]byte{0x11}, 16),
		iters:    1,
	}
	c.register(t)
	return c, c.scramEnroll(t, devID(0x01), "password").TokenHex
}

func (e *b2bEnv) bind(t *testing.T, vaultIDHex, bearer, personHex, role string) (*http.Response, bindMemberResp) {
	t.Helper()
	resp, body := sendJSON(t, http.MethodPost, e.srv.URL+"/b2b/vaults/"+vaultIDHex+"/members", bearer,
		bindMemberReq{PersonIDHex: personHex, Role: role})
	var br bindMemberResp
	_ = json.Unmarshal(body, &br)
	return resp, br
}

func (e *b2bEnv) remove(t *testing.T, vaultIDHex, bearer, personHex string) *http.Response {
	t.Helper()
	resp, _ := sendJSON(t, http.MethodDelete, e.srv.URL+"/b2b/vaults/"+vaultIDHex+"/members/"+personHex, bearer, nil)
	return resp
}

func (e *b2bEnv) resolve(t *testing.T, tokenHex string) (membership.Binding, error) {
	t.Helper()
	raw, err := hex.DecodeString(tokenHex)
	if err != nil {
		t.Fatalf("token hex: %v", err)
	}
	return e.h.MemberTokens().Resolve(ids.DeviceToken(raw))
}

func sendJSON(t *testing.T, method, url, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rdr = bytes.NewReader(buf)
	}
	req, _ := http.NewRequest(method, url, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	_, _ = out.ReadFrom(resp.Body)
	resp.Body.Close()
	return resp, out.Bytes()
}

func acct(t *testing.T, hexStr string) ids.AccountNumberHash {
	t.Helper()
	a, ok := ids.ParseAccountNumberHash(hexStr)
	if !ok {
		t.Fatalf("bad account hex %q", hexStr)
	}
	return a
}

// Criterion 1: a person account authenticates through the same SCRAM surface as
// a vault account, keyed by person_id_hash. No separate person-auth route exists
// (and must not: the server is blind to which kind of id it holds).
func TestB2B_PersonAccountAuthenticatesInTheExistingNamespace(t *testing.T) {
	e := newB2BEnv(t)
	if _, tok := e.account(t, b2bOwner, 0x0a); tok == "" {
		t.Fatal("a person account must register and receive a device token")
	}
	if _, tok := e.account(t, b2bVaultA, 0x0b); tok == "" {
		t.Fatal("a vault account must register and receive a device token")
	}
}

// Criterion 2: a membership binding issues a per-vault token, and a second vault
// requires its own binding — the first vault's token does not authorize the
// second.
func TestB2B_BindingIssuesPerVaultToken_SecondVaultNeedsSecondBinding(t *testing.T) {
	e := newB2BEnv(t)
	_, vaultTokA := e.account(t, b2bVaultA, 0x0b)
	_, vaultTokB := e.account(t, b2bVaultB, 0x0c)
	if _, tok := e.account(t, b2bOwner, 0x0a); tok == "" {
		t.Fatal("owner person must authenticate")
	}

	respA, bindA := e.bind(t, b2bVaultA, vaultTokA, b2bOwner, "owner")
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("bind owner to vault A: want 200, got %d", respA.StatusCode)
	}
	respB, bindB := e.bind(t, b2bVaultB, vaultTokB, b2bOwner, "owner")
	if respB.StatusCode != http.StatusOK {
		t.Fatalf("bind owner to vault B: want 200, got %d", respB.StatusCode)
	}
	if bindA.TokenHex == "" || bindB.TokenHex == "" {
		t.Fatal("each binding must issue a token")
	}
	if bindA.TokenHex == bindB.TokenHex {
		t.Fatal("two bindings must issue two distinct tokens")
	}

	// Each token resolves to exactly its own vault.
	ba, err := e.resolve(t, bindA.TokenHex)
	if err != nil || ba.Vault != acct(t, b2bVaultA) || ba.Person != b2bPersonID(t, b2bOwner) {
		t.Fatalf("vault A token resolved to %+v err=%v", ba, err)
	}
	bb, err := e.resolve(t, bindB.TokenHex)
	if err != nil || bb.Vault != acct(t, b2bVaultB) {
		t.Fatalf("vault B token resolved to %+v err=%v", bb, err)
	}

	// The vault-A owner token does NOT manage vault B: a second vault needs its
	// own binding. (b2bMember is unbound to B, so a 403 rather than 404 is the
	// assertion that the TOKEN, not the binding, was refused.)
	if resp := e.remove(t, b2bVaultB, bindA.TokenHex, b2bMember); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("vault A token used against vault B: want 403, got %d", resp.StatusCode)
	}
}

// Criterion 3: revoking one binding stops that vault and leaves the person's
// other vaults untouched.
func TestB2B_RevokeIsTargetedToOneVault(t *testing.T) {
	e := newB2BEnv(t)
	_, vaultTokA := e.account(t, b2bVaultA, 0x0b)
	_, vaultTokB := e.account(t, b2bVaultB, 0x0c)
	_, _ = e.account(t, b2bOwner, 0x0a)

	_, ownerA := e.bind(t, b2bVaultA, vaultTokA, b2bOwner, "owner")
	respB, ownerB := e.bind(t, b2bVaultB, vaultTokB, b2bOwner, "owner")
	if ownerA.TokenHex == "" || respB.StatusCode != http.StatusOK {
		t.Fatalf("owner bindings must be created: A=%q B=%d", ownerA.TokenHex, respB.StatusCode)
	}

	// The owner binds the same member to both vaults.
	respMA, memberA := e.bind(t, b2bVaultA, ownerA.TokenHex, b2bMember, "member")
	if respMA.StatusCode != http.StatusOK {
		t.Fatalf("bind member to vault A: want 200, got %d", respMA.StatusCode)
	}
	respMB, memberB := e.bind(t, b2bVaultB, ownerB.TokenHex, b2bMember, "member")
	if respMB.StatusCode != http.StatusOK {
		t.Fatalf("bind member to vault B: want 200, got %d", respMB.StatusCode)
	}

	// Revoke the member from vault A only.
	if resp := e.remove(t, b2bVaultA, ownerA.TokenHex, b2bMember); resp.StatusCode != http.StatusOK {
		t.Fatalf("remove member from vault A: want 200, got %d", resp.StatusCode)
	}

	// The vault-A token is dead; the vault-B token still resolves to vault B.
	if _, err := e.resolve(t, memberA.TokenHex); err == nil {
		t.Fatal("the revoked vault-A token must not resolve")
	}
	bb, err := e.resolve(t, memberB.TokenHex)
	if err != nil || bb.Vault != acct(t, b2bVaultB) {
		t.Fatalf("the vault-B token must survive a vault-A revoke, got %+v err=%v", bb, err)
	}

	// The owner's vault-A token is also untouched (the owner is not the removed
	// person), so A remains manageable.
	resp, _ := e.bind(t, b2bVaultA, ownerA.TokenHex, b2bOther, "member")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner must retain vault A management after a member revoke, got %d", resp.StatusCode)
	}

	// Re-bind the SAME member to vault A. This is the assertion that makes the
	// explicit Revoke load-bearing rather than decorative: Resolve is keyed on
	// the binding existing, so binding removal alone would let the member's OLD
	// token resolve AGAIN once the binding is re-created. The old token must stay
	// dead and only the fresh one resolve.
	respRe, reMemberA := e.bind(t, b2bVaultA, ownerA.TokenHex, b2bMember, "member")
	if respRe.StatusCode != http.StatusOK {
		t.Fatalf("re-bind member to vault A: want 200, got %d", respRe.StatusCode)
	}
	if _, err := e.resolve(t, memberA.TokenHex); err == nil {
		t.Fatal("the revoked token must not be resurrected by re-binding the member")
	}
	if _, err := e.resolve(t, reMemberA.TokenHex); err != nil {
		t.Fatalf("the re-bound member's fresh token must resolve: %v", err)
	}
}

// The singleton owner is fixed at registration; the guards around it are the
// difference between "a member cannot self-promote" and a broken role model.
func TestB2B_OwnerSingletonAndGuards(t *testing.T) {
	e := newB2BEnv(t)
	_, vaultTokA := e.account(t, b2bVaultA, 0x0b)
	_, _ = e.account(t, b2bOwner, 0x0a)

	_, ownerA := e.bind(t, b2bVaultA, vaultTokA, b2bOwner, "owner")
	if ownerA.TokenHex == "" {
		t.Fatal("owner registration must yield an owner token")
	}

	// (a) an owner token may not mint a second owner.
	if resp, _ := e.bind(t, b2bVaultA, ownerA.TokenHex, b2bMember, "owner"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("owner token promoting a second owner: want 400, got %d", resp.StatusCode)
	}
	// (b) the vault session may not re-register a different owner.
	if resp, _ := e.bind(t, b2bVaultA, vaultTokA, b2bMember, "owner"); resp.StatusCode != http.StatusConflict {
		t.Fatalf("vault session re-registering a different owner: want 409, got %d", resp.StatusCode)
	}
	// (c) the vault session may not add members (only an owner token can).
	if resp, _ := e.bind(t, b2bVaultA, vaultTokA, b2bMember, "member"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("vault session adding a member: want 400, got %d", resp.StatusCode)
	}
	// (d) the owner cannot be removed through the members route.
	if resp := e.remove(t, b2bVaultA, ownerA.TokenHex, b2bOwner); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("removing the owner: want 403, got %d", resp.StatusCode)
	}
	// (e) removing an unbound person is not_found.
	if resp := e.remove(t, b2bVaultA, ownerA.TokenHex, b2bAnybody); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("removing an unbound person: want 404, got %d", resp.StatusCode)
	}
	// (f) an unknown bearer is refused before any binding logic.
	if resp, _ := e.bind(t, b2bVaultA, "", b2bMember, "member"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no bearer: want 401, got %d", resp.StatusCode)
	}
}

// Criterion 4: an `NTV6` vault.meta, a retirement record and a `MYY5` profile are
// opaque bytes to the server. The store round-trips them byte-identically and
// parses nothing, so a 0x02 generation marker or a `profiles/<id>` layout never
// has a server-side reader to drift.
func TestB2B_ServerStoresB2BBlobsOpaquely(t *testing.T) {
	bs := store.NewMemStore()
	a := acct(t, b2bVaultA)

	// Bytes shaped like the three families that ride the opaque plane. The
	// leading `NTV6` is deliberate: a server that "helpfully" sniffed magic would
	// be the failure this test exists to catch.
	blob := append([]byte("NTV6\x02"), bytes.Repeat([]byte{0xAB, 0x00, 0xFF, 0x5A}, 256)...)

	var id ids.BlobID
	id[0] = 0x42
	if _, err := bs.PutBlob(a, id, blob); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	got, _, err := bs.GetBlob(a, id)
	if err != nil {
		t.Fatalf("GetBlob: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatal("stored B2B bytes must round-trip byte-identical")
	}
}

// Criterion 5: self-host and hosted run the same binary and the same handler, so
// the B2B route set must be present on the default handler rather than gated by
// configuration. Unauthenticated hits must be 401 (the routes exist and refuse),
// never 404/405 (the routes are absent).
func TestB2B_RouteSetIsPresentOnTheSharedHandler(t *testing.T) {
	e := newB2BEnv(t)
	resp, _ := sendJSON(t, http.MethodPost, e.srv.URL+"/b2b/vaults/"+b2bVaultA+"/members", "",
		bindMemberReq{PersonIDHex: b2bOwner, Role: "owner"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST members unauthenticated: want 401, got %d", resp.StatusCode)
	}
	resp, _ = sendJSON(t, http.MethodDelete, e.srv.URL+"/b2b/vaults/"+b2bVaultA+"/members/"+b2bOwner, "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("DELETE member unauthenticated: want 401, got %d", resp.StatusCode)
	}
}

func b2bPersonID(t *testing.T, hexStr string) membership.PersonID {
	t.Helper()
	p, ok := parsePersonID(hexStr)
	if !ok {
		t.Fatalf("bad person hex %q", hexStr)
	}
	return p
}

// ---- the person-session arm: a vault born under an identity (`NTV7`) ----
//
// A born-`NTV7` vault is published under the person's namespace and never holds a
// vault device session, so the two pre-existing arms cannot reach it: arm (1) needs
// a per-vault owner token it does not have yet, and arm (2) needs a vault account it
// never enrols. Every test below therefore sets the owner binding the way publishing
// does (`Handler.BindOwner`, owner-at-first-write) and then uses the OWNER'S PERSON
// token, which is the /auth device token of the person account.

// publishedPersonBornVault is the minimum state a born-`NTV7` vault has on the
// server, and deliberately no more: an owner binding and no vault account.
func publishedPersonBornVault(t *testing.T, e *b2bEnv, vaultHex, ownerHex string) {
	t.Helper()
	if err := e.h.BindOwner(acct(t, vaultHex), acct(t, ownerHex)); err != nil {
		t.Fatalf("publish (bind owner): %v", err)
	}
}

// The owner's own person session binds a member, and the per-vault token it issues
// resolves to that member on that vault.
func TestB2B_PersonSessionBindsAMember(t *testing.T) {
	e := newB2BEnv(t)
	_, ownerPersonTok := e.account(t, b2bOwner, 0x0a)
	publishedPersonBornVault(t, e, b2bVaultA, b2bOwner)

	resp, bound := e.bind(t, b2bVaultA, ownerPersonTok, b2bMember, "member")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("person session binding a member: want 200, got %d", resp.StatusCode)
	}
	if bound.TokenHex == "" {
		t.Fatal("the binding must issue a per-vault token")
	}
	got, err := e.resolve(t, bound.TokenHex)
	if err != nil {
		t.Fatalf("the issued token must resolve: %v", err)
	}
	if got.Vault != acct(t, b2bVaultA) || got.Person != b2bPersonID(t, b2bMember) {
		t.Fatalf("token resolved to %+v", got)
	}
	if got.Role != membership.RoleMember {
		t.Fatalf("a member binding must carry the member role, got %v", got.Role)
	}
	// The device that asked is recorded, so one device revocation ends this access
	// too. Without it the token would be unattributable and survive a revocation.
	if got.Device == (ids.DeviceID{}) {
		t.Fatal("a token minted through a person session must name its device")
	}
}

// A person session that is not the vault's owner is refused, and the refusal is
// about AUTHORITY (403) rather than identity (401), which a client reads as "my
// token died" and would answer by re-enrolling.
func TestB2B_PersonSessionCannotBindOnAVaultItDoesNotOwn(t *testing.T) {
	e := newB2BEnv(t)
	_, strangerTok := e.account(t, b2bOther, 0x0d)
	publishedPersonBornVault(t, e, b2bVaultA, b2bOwner)

	resp, _ := e.bind(t, b2bVaultA, strangerTok, b2bAnybody, "member")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a non-owner person session binding a member: want 403, got %d", resp.StatusCode)
	}
	// …and an unbound vault (never published) is refused the same way, so this arm
	// cannot be used to claim a namespace.
	if resp, _ := e.bind(t, b2bVaultB, strangerTok, b2bAnybody, "owner"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("claiming an unowned vault from a person session: want 403, got %d", resp.StatusCode)
	}
}

// A MEMBER's own session must not add members to the vault it joined: the role is
// checked, not merely the presence of a binding.
func TestB2B_MemberSessionCannotBindAnotherMember(t *testing.T) {
	e := newB2BEnv(t)
	_, ownerPersonTok := e.account(t, b2bOwner, 0x0a)
	_, memberPersonTok := e.account(t, b2bMember, 0x0e)
	publishedPersonBornVault(t, e, b2bVaultA, b2bOwner)
	if err := e.h.members.BindMember(acct(t, b2bVaultA), b2bPersonID(t, b2bMember)); err != nil {
		t.Fatalf("bind the member: %v", err)
	}

	resp, _ := e.bind(t, b2bVaultA, memberPersonTok, b2bAnybody, "member")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a member session binding a member: want 403, got %d", resp.StatusCode)
	}
	// The owner can still do it, so the refusal is about the caller's role rather
	// than about the route being shut.
	if resp, _ := e.bind(t, b2bVaultA, ownerPersonTok, b2bOther, "member"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner must still be able to bind: want 200, got %d", resp.StatusCode)
	}
}

// The owner's person session re-mints its OWN owner token (idempotent), which is what
// the client needs after a restart dropped its device-local copy; and it cannot make
// a second person the owner.
func TestB2B_PersonSessionRemintsItsOwnOwnerTokenAndRefusesASecondOwner(t *testing.T) {
	e := newB2BEnv(t)
	_, ownerPersonTok := e.account(t, b2bOwner, 0x0a)
	publishedPersonBornVault(t, e, b2bVaultA, b2bOwner)

	resp, own := e.bind(t, b2bVaultA, ownerPersonTok, b2bOwner, "owner")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-minting the owner's own token: want 200, got %d", resp.StatusCode)
	}
	if own.TokenHex == "" {
		t.Fatal("the re-mint must issue a token")
	}
	got, err := e.resolve(t, own.TokenHex)
	if err != nil || got.Role != membership.RoleOwner || got.Person != b2bPersonID(t, b2bOwner) {
		t.Fatalf("owner re-mint resolved to %+v err=%v", got, err)
	}

	resp, _ = e.bind(t, b2bVaultA, ownerPersonTok, b2bOther, "owner")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("making a second person owner: want 400, got %d", resp.StatusCode)
	}
	if owner, _ := e.h.members.OwnerOf(acct(t, b2bVaultA)); owner.Person != b2bPersonID(t, b2bOwner) {
		t.Fatalf("the owner must be unchanged, got %+v", owner)
	}
}
