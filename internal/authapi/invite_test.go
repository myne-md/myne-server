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

// A sealed invite is stored opaquely, visible only to its recipient, released on
// claim, and left in place for an idempotent re-claim by that same recipient.
func TestB2B_InviteRelay_StoredSealedListedAndReClaimable(t *testing.T) {
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

	// A re-claim by the SAME recipient returns the invite again (member-devices).
	// A claim by a DIFFERENT account was refused 404 above and stays refused.
	resp, body = e.claim(t, memberTok, inviteID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-claim: want 200, got %d: %s", resp.StatusCode, body)
	}
	var re claimInviteResp
	if err := json.Unmarshal(body, &re); err != nil {
		t.Fatal(err)
	}
	rePayload, err := base64.StdEncoding.DecodeString(re.PayloadB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rePayload, payload) {
		t.Fatalf("re-claimed payload = %q, want %q", rePayload, payload)
	}
	if _, err := e.resolve(t, re.TokenHex); err != nil {
		t.Fatalf("re-claim token must resolve: %v", err)
	}
	// The list now reports it claimed rather than hiding it.
	if mine := listFor(memberTok); len(mine) != 1 || !mine[0].Claimed {
		t.Fatalf("post-claim list = %+v, want the invite marked claimed", mine)
	}
}

// A member's SECOND device re-claims the invite the owner already issued to that
// same person: the claim is idempotent, returning the stored sealed payload and
// minting a fresh per-vault token that RESOLVES, so a member can bring a second
// device without the owner (member-devices). Every other caller is unchanged.
func TestB2B_InviteRelay_ReClaimBySameRecipientIsIdempotent(t *testing.T) {
	e := newInviteEnv(t)
	// Two device sessions on ONE person account: the account is person-level, so
	// both devices authenticate as the same person id (§3.1a). Device 1 is the
	// self-approving first device; device 2 comes in on the recovery path, which
	// self-approves too, so both hold a person session without an owner's help.
	c := &testClient{
		srv:      e.srv,
		username: b2bMember,
		account:  b2bMember,
		secret:   bytes.Repeat([]byte{0x0d}, 32),
		salt:     bytes.Repeat([]byte{0x11}, 16),
		iters:    1,
	}
	c.register(t)
	memberTokDevice1 := c.scramEnroll(t, devID(0x01), "password").TokenHex
	memberTokDevice2 := c.scramEnroll(t, devID(0x02), "recovery").TokenHex
	_, otherTok := e.account(t, b2bOther, 0x0e)

	payload := []byte("sealed invite payload for the member's second device")
	_, inviteID, _ := e.createInvite(t, e.ownerA, b2bMember, payload)

	// Device 1 claims first, exactly as before.
	resp, body := e.claim(t, memberTokDevice1, inviteID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first claim: want 200, got %d: %s", resp.StatusCode, body)
	}
	var first claimInviteResp
	if err := json.Unmarshal(body, &first); err != nil {
		t.Fatal(err)
	}
	if b, err := e.resolve(t, first.TokenHex); err != nil || b.Vault != acct(t, b2bVaultA) {
		t.Fatalf("first claim token must resolve to vault A: %+v err=%v", b, err)
	}

	// Device 2 re-claims the same invite: 200, the payload byte-identically, and
	// a fresh token that actually resolves to the same (member, vault A) binding.
	resp, body = e.claim(t, memberTokDevice2, inviteID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-claim by the same recipient: want 200, got %d: %s", resp.StatusCode, body)
	}
	var again claimInviteResp
	if err := json.Unmarshal(body, &again); err != nil {
		t.Fatal(err)
	}
	got, err := base64.StdEncoding.DecodeString(again.PayloadB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("re-claimed payload = %q, want %q", got, payload)
	}
	binding, err := e.resolve(t, again.TokenHex)
	if err != nil {
		t.Fatalf("re-claim token must resolve, not merely be non-empty: %v", err)
	}
	if binding.Vault != acct(t, b2bVaultA) || binding.Person != b2bPersonID(t, b2bMember) {
		t.Fatalf("re-claim token bound to %+v, want (member, vault A)", binding)
	}

	// The owner's claimed-versus-pending view still reports the invite claimed
	// after a second claim rather than resetting it.
	_, vaultBody := sendJSON(t, http.MethodGet, e.srv.URL+"/b2b/vaults/"+b2bVaultA+"/invites", e.ownerA, nil)
	var vaultEnv struct {
		Invites []vaultInviteWire `json:"invites"`
	}
	if err := json.Unmarshal(vaultBody, &vaultEnv); err != nil {
		t.Fatal(err)
	}
	if len(vaultEnv.Invites) != 1 || !vaultEnv.Invites[0].Claimed {
		t.Fatalf("owner vault list after re-claim = %+v, want the invite claimed", vaultEnv.Invites)
	}

	// A different person is still 404 (not 409, not 403) even though the invite
	// is now claimed, and an unknown id is the same 404: the idempotency rule
	// widens no enumeration signal.
	if resp, _ := e.claim(t, otherTok, inviteID); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("claim by another account on a claimed invite: want 404, got %d", resp.StatusCode)
	}
	if resp, _ := e.claim(t, memberTokDevice2, "00112233445566778899aabbccddeeff"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown invite id: want 404, got %d", resp.StatusCode)
	}
}

// A member the owner has removed cannot walk back into the vault by re-claiming
// the invite the owner originally sent. The invite is retained so that a
// still-bound recipient can re-claim idempotently, and the idempotency is scoped
// to a binding that still stands, so a re-claim after a revoke is refused and
// mints nothing.
func TestB2B_RemovedMemberCannotReClaimTheStoredInvite(t *testing.T) {
	e := newInviteEnv(t)
	_, memberTok := e.account(t, b2bMember, 0x0d)

	vault := acct(t, b2bVaultA)
	person := b2bPersonID(t, b2bMember)

	_, inviteID, _ := e.createInvite(t, e.ownerA, b2bMember, []byte("x"))

	// The member claims and is bound, and the claim mints a working token.
	resp, body := e.claim(t, memberTok, inviteID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first claim: want 200, got %d: %s", resp.StatusCode, body)
	}
	var cr claimInviteResp
	if err := json.Unmarshal(body, &cr); err != nil {
		t.Fatal(err)
	}
	if _, err := e.resolve(t, cr.TokenHex); err != nil {
		t.Fatalf("first claim token must resolve: %v", err)
	}
	if _, bound := e.h.Membership().Role(vault, person); !bound {
		t.Fatal("the claiming member must be bound after the first claim")
	}

	// The owner removes the member through the membership route.
	if resp := e.remove(t, b2bVaultA, e.ownerA, b2bMember); resp.StatusCode != http.StatusOK {
		t.Fatalf("remove member: want 200, got %d", resp.StatusCode)
	}

	// The same person re-claims the same stored invite, carrying the same person
	// session they still hold. It must be refused: the binding it would re-create
	// is gone, and a retained invite must not be a way back in.
	resp, body = e.claim(t, memberTok, inviteID)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("re-claim by a removed member: want a refusal, got 200: %s", body)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("re-claim by a removed member: want 404, got %d: %s", resp.StatusCode, body)
	}
	// No token was minted: the body is the error shape, not a claim response.
	var errBody map[string]string
	if err := json.Unmarshal(body, &errBody); err != nil {
		t.Fatal(err)
	}
	if _, ok := errBody["token_hex"]; ok {
		t.Fatalf("a refused re-claim must mint no token, got %s", body)
	}
	// The membership read still says the removed person is not a member, so the
	// refusal left no binding behind.
	if _, bound := e.h.Membership().Role(vault, person); bound {
		t.Fatal("a refused re-claim must not re-create the membership binding")
	}
	// The token the first claim minted stays revoked.
	if _, err := e.resolve(t, cr.TokenHex); err == nil {
		t.Fatal("a removed member's token must stay revoked after a refused re-claim")
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
