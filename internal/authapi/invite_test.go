// SPDX-License-Identifier: AGPL-3.0

package authapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

type inviteEnv struct {
	*b2bEnv
	// ownerA is the owner's per-vault token for vault A.
	ownerA string
}

// newInviteEnv builds vault A with an owner and returns the owner token.
func newInviteEnv(t *testing.T) *inviteEnv {
	t.Helper()
	e := newB2BEnv(t)
	_, vaultTokA := e.account(t, b2bVaultA, 0x0b)
	_, _ = e.account(t, b2bOwner, 0x0a)
	_, ownerA := e.bind(t, b2bVaultA, vaultTokA, b2bOwner, "owner")
	if ownerA.TokenHex == "" {
		t.Fatal("owner binding must issue a token")
	}
	return &inviteEnv{b2bEnv: e, ownerA: ownerA.TokenHex}
}

func (e *inviteEnv) createInvite(t *testing.T, bearer, recipientHex string, payload []byte) (*http.Response, string, []byte) {
	t.Helper()
	resp, body := sendJSON(t, http.MethodPost, e.srv.URL+"/b2b/invites", bearer, createInviteReq{
		RecipientPersonIDHex: recipientHex,
		PayloadB64:           base64.StdEncoding.EncodeToString(payload),
	})
	var cr createInviteResp
	_ = json.Unmarshal(body, &cr)
	return resp, cr.InviteIDHex, body
}

func (e *inviteEnv) claim(t *testing.T, bearer, inviteIDHex string) (*http.Response, []byte) {
	t.Helper()
	return sendJSON(t, http.MethodPost, e.srv.URL+"/b2b/invites/"+inviteIDHex+"/claim", bearer, nil)
}

// A sealed invite is stored opaquely, visible only to its recipient, and
// consumed by exactly one claim.
func TestB2B_InviteRelay_StoredSealedAndClaimedOnce(t *testing.T) {
	e := newInviteEnv(t)
	_, memberTok := e.account(t, b2bMember, 0x0d)
	_, otherTok := e.account(t, b2bOther, 0x0e)

	payload := []byte("sealed invite payload, opaque to the server through and through")
	resp, inviteID, body := e.createInvite(t, e.ownerA, b2bMember, payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create invite: want 200, got %d: %s", resp.StatusCode, body)
	}
	if inviteID == "" {
		t.Fatal("create invite must return an invite id")
	}

	// The recipient can list it; a different account sees nothing.
	listFor := func(bearer string) []inviteWire {
		t.Helper()
		resp, body := sendJSON(t, http.MethodGet, e.srv.URL+"/b2b/invites", bearer, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list invites: want 200, got %d: %s", resp.StatusCode, body)
		}
		var lr struct {
			Invites []inviteWire `json:"invites"`
		}
		if err := json.Unmarshal(body, &lr); err != nil {
			t.Fatal(err)
		}
		return lr.Invites
	}
	mine := listFor(memberTok)
	if len(mine) != 1 || mine[0].InviteIDHex != inviteID || mine[0].VaultAccountHashHex != b2bVaultA || mine[0].Claimed {
		t.Fatalf("recipient list = %+v, want the one unclaimed invite for vault A", mine)
	}
	if other := listFor(otherTok); len(other) != 0 {
		t.Fatalf("a different account must see no invites, got %+v", other)
	}

	// A claim by a different account is refused and must not reveal the invite.
	if resp, _ := e.claim(t, otherTok, inviteID); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("claim by another account: want 404, got %d", resp.StatusCode)
	}

	// The recipient claims it: payload round-trips byte-identically and a
	// per-vault token is issued and scoped to (member, vault A).
	resp, body = e.claim(t, memberTok, inviteID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("claim: want 200, got %d: %s", resp.StatusCode, body)
	}
	var cr claimInviteResp
	if err := json.Unmarshal(body, &cr); err != nil {
		t.Fatal(err)
	}
	got, err := base64.StdEncoding.DecodeString(cr.PayloadB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("claimed payload = %q, want %q", got, payload)
	}
	binding, err := e.resolve(t, cr.TokenHex)
	if err != nil {
		t.Fatalf("claim token must resolve: %v", err)
	}
	if binding.Vault != acct(t, b2bVaultA) || binding.Person != b2bPersonID(t, b2bMember) {
		t.Fatalf("claim token bound to %+v, want (member, vault A)", binding)
	}

	// A claimed invite is not re-claimable.
	if resp, _ := e.claim(t, memberTok, inviteID); resp.StatusCode != http.StatusConflict {
		t.Fatalf("second claim: want 409, got %d", resp.StatusCode)
	}
	// The list now reports it claimed rather than hiding it.
	if mine := listFor(memberTok); len(mine) != 1 || !mine[0].Claimed {
		t.Fatalf("post-claim list = %+v, want the invite marked claimed", mine)
	}
}

// The outer routing frame is deliberately reduced: only the invite id, the vault
// id and (for the owner) the recipient id travel outside the sealed payload. If
// a future edit added a fingerprint or a public half to these responses, the
// server would be reading material decisions/protocol/0599 moved inside.
func TestB2B_InviteRelay_FrameCarriesOnlyRoutingFields(t *testing.T) {
	e := newInviteEnv(t)
	_, memberTok := e.account(t, b2bMember, 0x0d)

	_, inviteID, body := e.createInvite(t, e.ownerA, b2bMember, []byte("x"))
	assertKeys(t, body, "invite_id_hex", "vault_account_hash_hex", "recipient_person_id_hex")

	_, listBody := sendJSON(t, http.MethodGet, e.srv.URL+"/b2b/invites", memberTok, nil)
	var env map[string][]map[string]json.RawMessage
	if err := json.Unmarshal(listBody, &env); err != nil {
		t.Fatal(err)
	}
	items, ok := env["invites"]
	if !ok || len(items) != 1 {
		t.Fatalf("list body = %s, want one invites entry", listBody)
	}
	assertKeys(t, jsonBytes(t, items[0]), "invite_id_hex", "vault_account_hash_hex", "claimed")

	_, claimBody := e.claim(t, memberTok, inviteID)
	assertKeys(t, claimBody, "payload_b64", "vault_account_hash_hex", "token_hex")

	// The owner-side list exposes the recipient id (which the owner supplied)
	// and the claimed flag, and still no payload.
	_, vaultBody := sendJSON(t, http.MethodGet, e.srv.URL+"/b2b/vaults/"+b2bVaultA+"/invites", e.ownerA, nil)
	var vaultEnv map[string][]map[string]json.RawMessage
	if err := json.Unmarshal(vaultBody, &vaultEnv); err != nil {
		t.Fatal(err)
	}
	vaultItems, ok := vaultEnv["invites"]
	if !ok || len(vaultItems) != 1 {
		t.Fatalf("vault list body = %s, want one invites entry", vaultBody)
	}
	assertKeys(t, jsonBytes(t, vaultItems[0]), "invite_id_hex", "recipient_person_id_hex", "claimed")
}

// Only the vault's owner may address an invite for it, and only a registered
// account may claim: the two directions have different authorities.
func TestB2B_InviteRelay_Authorization(t *testing.T) {
	e := newInviteEnv(t)
	_, memberTok := e.account(t, b2bMember, 0x0d)

	// A member token is not an owner token: it cannot post an invite.
	if resp, _, _ := e.createInvite(t, memberTok, b2bOther, []byte("x")); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("member posting an invite: want 401, got %d", resp.StatusCode)
	}
	// An unregistered bearer cannot list or claim.
	if resp, _ := sendJSON(t, http.MethodGet, e.srv.URL+"/b2b/invites", "deadbeef", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown bearer listing: want 401, got %d", resp.StatusCode)
	}
	// A malformed recipient id is refused at the door.
	if resp, _, _ := e.createInvite(t, e.ownerA, "not-hex", []byte("x")); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed recipient: want 400, got %d", resp.StatusCode)
	}
	// An over-cap payload is refused rather than stored.
	if resp, _, _ := e.createInvite(t, e.ownerA, b2bMember, bytes.Repeat([]byte{9}, maxInviteBytes+1)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("over-cap payload: want 400, got %d", resp.StatusCode)
	}
}

// The owner-side vault list is the claimed-versus-pending view: the owner sees
// the invitations it sent (with the recipient id it supplied and the claimed
// flag), while a member token cannot read it and no payload is ever released.
func TestB2B_VaultInviteList_OwnerSeesClaimedVersusPending(t *testing.T) {
	e := newInviteEnv(t)
	_, memberTok := e.account(t, b2bMember, 0x0d)

	listVault := func(bearer string) (*http.Response, []vaultInviteWire) {
		t.Helper()
		resp, body := sendJSON(t, http.MethodGet, e.srv.URL+"/b2b/vaults/"+b2bVaultA+"/invites", bearer, nil)
		var lr struct {
			Invites []vaultInviteWire `json:"invites"`
		}
		if resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(body, &lr); err != nil {
				t.Fatal(err)
			}
		}
		return resp, lr.Invites
	}

	// Before any invite, the owner's list is empty (not an error).
	if resp, got := listVault(e.ownerA); resp.StatusCode != http.StatusOK || len(got) != 0 {
		t.Fatalf("empty vault list: want 200 with no rows, got %d %+v", resp.StatusCode, got)
	}

	_, inviteID, _ := e.createInvite(t, e.ownerA, b2bMember, []byte("x"))

	resp, rows := listVault(e.ownerA)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner vault list: want 200, got %d", resp.StatusCode)
	}
	if len(rows) != 1 || rows[0].InviteIDHex != inviteID || rows[0].RecipientPersonIDHex != b2bMember || rows[0].Claimed {
		t.Fatalf("owner vault list = %+v, want one unclaimed invite to the member", rows)
	}

	// A member's per-vault token is not an owner token: it cannot read the
	// vault-side list. (A bare /auth account token resolves to no membership at
	// all, which is the 401 arm; the 403 arm needs the bound member token.)
	claimResp, claimBody := e.claim(t, memberTok, inviteID)
	if claimResp.StatusCode != http.StatusOK {
		t.Fatalf("claim: want 200, got %d", claimResp.StatusCode)
	}
	var cr claimInviteResp
	if err := json.Unmarshal(claimBody, &cr); err != nil {
		t.Fatal(err)
	}
	if resp, _ := listVault(cr.TokenHex); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member reading the vault list: want 403, got %d", resp.StatusCode)
	}

	// After the member claims, the owner sees it marked claimed.
	if resp, rows := listVault(e.ownerA); resp.StatusCode != http.StatusOK || len(rows) != 1 || !rows[0].Claimed {
		t.Fatalf("post-claim owner list: want the invite claimed, got %d %+v", resp.StatusCode, rows)
	}
}

func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// assertKeys asserts a JSON object has EXACTLY the given top-level keys.
func assertKeys(t *testing.T, body []byte, want ...string) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("body is not a JSON object: %v (%s)", err, body)
	}
	if len(m) != len(want) {
		t.Fatalf("frame keys = %v, want exactly %v", keysOf(m), want)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Fatalf("frame missing key %q (has %v)", k, keysOf(m))
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
