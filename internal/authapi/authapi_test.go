// SPDX-License-Identifier: AGPL-3.0-only

package authapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/auth/scram"
	"github.com/myne-md/myne-server/internal/ids"
)

// testClient drives the SCRAM client side using the Go scram package (the same
// math protocol::scram_client_proof implements on the real client).
type testClient struct {
	srv      *httptest.Server
	username string
	account  string
	secret   []byte
	salt     []byte
	iters    int
}

func newEnv(t *testing.T) *testClient {
	t.Helper()
	reg := auth.NewRegistry()
	tokens := auth.NewTokenStore(reg)
	mux := http.NewServeMux()
	New(reg, tokens).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := &testClient{
		srv: srv,
		// AS9: the SCRAM username IS the account-hash hex (canonical lowercase).
		username: strings.Repeat("42", 16),
		account:  strings.Repeat("42", 16),
		secret:   bytes.Repeat([]byte{0xab}, 32),
		salt:     bytes.Repeat([]byte{0x11}, 16),
		iters:    1,
	}
	return c
}

func postJSON(t *testing.T, url, token string, body any) (*http.Response, []byte) {
	t.Helper()
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
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

func (c *testClient) register(t *testing.T) {
	t.Helper()
	cred, err := scram.MakeCredential(c.secret, c.salt, c.iters)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := postJSON(t, c.srv.URL+"/auth/register", "", registerReq{
		AccountHashHex: c.account,
		Username:       c.username,
		SaltHex:        hex.EncodeToString(c.salt),
		Iterations:     c.iters,
		StoredKeyHex:   hex.EncodeToString(cred.StoredKey),
		ServerKeyHex:   hex.EncodeToString(cred.ServerKey),
	})
	if resp.StatusCode != 200 {
		t.Fatalf("register status %d: %s", resp.StatusCode, body)
	}
}

// scramEnroll runs init+final for device `dev` on `path`; returns the response.
func (c *testClient) scramEnroll(t *testing.T, dev ids.DeviceID, path string) scramFinalResp {
	t.Helper()
	clientNonce := "cn-" + hex.EncodeToString(dev[:4])

	resp, body := postJSON(t, c.srv.URL+"/auth/scram/init", "", scramInitReq{
		AccountHashHex: c.account,
		Username:       c.username,
		ClientNonce:    clientNonce,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("init status %d: %s", resp.StatusCode, body)
	}
	var ir scramInitResp
	if err := json.Unmarshal(body, &ir); err != nil {
		t.Fatal(err)
	}

	cred, _ := scram.MakeCredential(c.secret, c.salt, c.iters)
	proof, _, err := scram.ClientProof(c.secret, cred, c.username, clientNonce, ir.CombinedNonce, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientFinal := scram.ClientFinalMessage(ir.CombinedNonce, nil, proof)

	resp, body = postJSON(t, c.srv.URL+"/auth/scram/final", "", scramFinalReq{
		HandshakeID: ir.HandshakeID,
		ClientFinal: clientFinal,
		DeviceIDHex: hex.EncodeToString(dev[:]),
		Path:        path,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("final status %d: %s", resp.StatusCode, body)
	}
	var fr scramFinalResp
	if err := json.Unmarshal(body, &fr); err != nil {
		t.Fatal(err)
	}
	return fr
}

func devID(b byte) ids.DeviceID {
	var d ids.DeviceID
	for i := range d {
		d[i] = b
	}
	return d
}

func devHex(b byte) string {
	d := devID(b)
	return hex.EncodeToString(d[:])
}

func TestEnroll_FirstDevicePassword_SelfApprovesAndGetsToken(t *testing.T) {
	c := newEnv(t)
	c.register(t)
	fr := c.scramEnroll(t, devID(0x01), "password")
	if !fr.Approved || fr.TokenHex == "" {
		t.Fatalf("first password device should self-approve with a token, got %+v", fr)
	}
	if fr.ServerSignatureB64 == "" {
		t.Fatalf("missing server signature (mutual auth)")
	}
}

func TestEnroll_RecoveryPathSelfApproves(t *testing.T) {
	c := newEnv(t)
	c.register(t)
	// First device exists (password), so a second device would normally be
	// pending — but the recovery path self-approves (bootstrap exception).
	_ = c.scramEnroll(t, devID(0x01), "password")
	fr := c.scramEnroll(t, devID(0x02), "recovery")
	if !fr.Approved || fr.TokenHex == "" {
		t.Fatalf("recovery path should self-approve, got %+v", fr)
	}
}

func TestEnroll_SecondPasswordDevice_PendingThenApproved(t *testing.T) {
	c := newEnv(t)
	c.register(t)

	// First device → token (the approver).
	first := c.scramEnroll(t, devID(0x01), "password")
	if !first.Approved {
		t.Fatalf("first device must be approved")
	}

	// Second password device → pending (no token yet).
	second := c.scramEnroll(t, devID(0x02), "password")
	if second.Approved || second.TokenHex != "" {
		t.Fatalf("second password device must be pending, got %+v", second)
	}

	// The first device approves the second.
	resp, body := postJSON(t, c.srv.URL+"/auth/devices/approve", first.TokenHex, deviceActionReq{
		DeviceIDHex: devHex(0x02),
	})
	if resp.StatusCode != 200 {
		t.Fatalf("approve status %d: %s", resp.StatusCode, body)
	}

	// The second device re-runs SCRAM → now gets its token (CompleteApproval).
	second2 := c.scramEnroll(t, devID(0x02), "password")
	if !second2.Approved || second2.TokenHex == "" {
		t.Fatalf("approved device should now get a token, got %+v", second2)
	}
}

func TestScramFinal_WrongSecretRejected(t *testing.T) {
	c := newEnv(t)
	c.register(t)
	clientNonce := "cn"
	_, body := postJSON(t, c.srv.URL+"/auth/scram/init", "", scramInitReq{
		AccountHashHex: c.account, Username: c.username, ClientNonce: clientNonce,
	})
	var ir scramInitResp
	_ = json.Unmarshal(body, &ir)

	// Compute the proof with the WRONG secret.
	wrong := bytes.Repeat([]byte{0x99}, 32)
	cred, _ := scram.MakeCredential(wrong, c.salt, c.iters)
	proof, _, _ := scram.ClientProof(wrong, cred, c.username, clientNonce, ir.CombinedNonce, nil)
	clientFinal := scram.ClientFinalMessage(ir.CombinedNonce, nil, proof)

	resp, _ := postJSON(t, c.srv.URL+"/auth/scram/final", "", scramFinalReq{
		HandshakeID: ir.HandshakeID, ClientFinal: clientFinal,
		DeviceIDHex: devHex(0x01), Path: "password",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong secret should 401, got %d", resp.StatusCode)
	}
}

func TestDevices_ListAndRevoke(t *testing.T) {
	c := newEnv(t)
	c.register(t)
	tok := c.scramEnroll(t, devID(0x01), "password").TokenHex

	// List devices (authed).
	req, _ := http.NewRequest(http.MethodGet, c.srv.URL+"/auth/devices", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("devices status %d", resp.StatusCode)
	}
	var dl struct {
		Devices []deviceWire `json:"devices"`
	}
	_ = json.Unmarshal(body.Bytes(), &dl)
	if len(dl.Devices) != 1 || !dl.Devices[0].Approved {
		t.Fatalf("expected 1 approved device, got %+v", dl.Devices)
	}

	// Revoke device 0x01 → its token stops authenticating.
	rresp, rbody := postJSON(t, c.srv.URL+"/auth/devices/revoke", tok, deviceActionReq{
		DeviceIDHex: devHex(0x01),
	})
	if rresp.StatusCode != 200 {
		t.Fatalf("revoke status %d: %s", rresp.StatusCode, rbody)
	}
	// The revoked token no longer lists devices.
	req2, _ := http.NewRequest(http.MethodGet, c.srv.URL+"/auth/devices", nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	resp2, _ := http.DefaultClient.Do(req2)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token should 401, got %d", resp2.StatusCode)
	}
}

// The wire half of MYND-574 task 94: a revoked device's 401 carries
// `device_revoked`, and an unknown token's 401 carries `unauthenticated`. Same
// status, two codes — and the pair is the test, because a server that answered
// `device_revoked` to everything would pass either assertion alone while making
// a web client erase its local copy on any stale token.
func TestDevices_RevokedTokenGetsDeviceRevokedCode(t *testing.T) {
	c := newEnv(t)
	c.register(t)
	tok := c.scramEnroll(t, devID(0x01), "password").TokenHex

	rresp, rbody := postJSON(t, c.srv.URL+"/auth/devices/revoke", tok, deviceActionReq{
		DeviceIDHex: devHex(0x01),
	})
	if rresp.StatusCode != 200 {
		t.Fatalf("revoke status %d: %s", rresp.StatusCode, rbody)
	}

	codeFor := func(bearer string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, c.srv.URL+"/auth/devices", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var eb struct {
			ErrorCode string `json:"error_code"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&eb)
		return resp.StatusCode, eb.ErrorCode
	}

	status, code := codeFor(tok)
	if status != http.StatusUnauthorized || code != "device_revoked" {
		t.Fatalf("revoked device: want 401 device_revoked, got %d %q", status, code)
	}

	// A token this server never issued must NOT be reported as revoked — it has
	// no idea, and guessing is what would make the code destructive.
	status, code = codeFor("ab" + tok[2:])
	if status != http.StatusUnauthorized || code != "unauthenticated" {
		t.Fatalf("unknown token: want 401 unauthenticated, got %d %q", status, code)
	}
}

func TestRegister_DuplicateRejected(t *testing.T) {
	c := newEnv(t)
	c.register(t)
	cred, _ := scram.MakeCredential(c.secret, c.salt, c.iters)
	resp, _ := postJSON(t, c.srv.URL+"/auth/register", "", registerReq{
		AccountHashHex: c.account, Username: c.username, SaltHex: hex.EncodeToString(c.salt),
		Iterations: c.iters, StoredKeyHex: hex.EncodeToString(cred.StoredKey),
		ServerKeyHex: hex.EncodeToString(cred.ServerKey),
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate register should 409, got %d", resp.StatusCode)
	}
}

// AS9: the SCRAM username MUST be the canonical lowercase hex of the 16-byte
// account hash. A raw (display-form) account number — or any other string — is
// rejected at register, so the persisted auth state structurally cannot contain
// a raw bearer credential, even from an outdated client.
func TestRegister_RejectsNonHashUsername(t *testing.T) {
	c := newEnv(t)
	cred, err := scram.MakeCredential(c.secret, c.salt, c.iters)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"MY-ABCD-EFGH-JKMN-PQRS-T", // display-form account number
		"alice",                    // arbitrary username
		strings.Repeat("ab", 16),   // valid hash shape, but a DIFFERENT account's
		"",                         // empty
	} {
		resp, _ := postJSON(t, c.srv.URL+"/auth/register", "", registerReq{
			AccountHashHex: c.account,
			Username:       bad,
			SaltHex:        hex.EncodeToString(c.salt),
			Iterations:     c.iters,
			StoredKeyHex:   hex.EncodeToString(cred.StoredKey),
			ServerKeyHex:   hex.EncodeToString(cred.ServerKey),
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("register with username %q: want 400, got %d", bad, resp.StatusCode)
		}
	}
}

// Init rejects a non-canonical username with the SAME 401 as unknown-account /
// wrong-username — no enumeration signal, and no raw-form identity accepted on
// any pre-auth surface.
func TestScramInit_RejectsNonCanonicalUsernameUniformly(t *testing.T) {
	c := newEnv(t)
	c.register(t)
	for _, bad := range []string{"MY-ABCD-EFGH-JKMN-PQRS-T", strings.Repeat("ab", 16), "alice"} {
		resp, _ := postJSON(t, c.srv.URL+"/auth/scram/init", "", scramInitReq{
			AccountHashHex: c.account,
			Username:       bad,
			ClientNonce:    "cn",
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("init with username %q: want 401, got %d", bad, resp.StatusCode)
		}
	}
}

// A client-side whole-vault re-key changes `derive_subkey(root_key, ServerAuth)`,
// so the account's SCRAM verifier has to change with it (`protocol.md` §10.4,
// myne-md/myne#429). `/auth/register` is first-write-only and must stay that way,
// so the replace lives behind the bearer token — and the account comes from the
// SESSION, never from the body.
//
// Each assertion below is a separate way this could be wrong: unauthenticated
// must not replace, an authenticated replace must actually take effect (the OLD
// secret stops working AND the new one starts), and an account with no verifier
// must not be created through this route.
func TestReplaceVerifier(t *testing.T) {
	c := newEnv(t)
	c.register(t)
	fr := c.scramEnroll(t, devID(0x01), "password")
	if fr.TokenHex == "" {
		t.Fatal("enrolment must yield a token to authenticate the replace with")
	}

	newSecret := bytes.Repeat([]byte{0xcd}, 32)
	newSalt := bytes.Repeat([]byte{0x22}, 16)
	newCred, err := scram.MakeCredential(newSecret, newSalt, c.iters)
	if err != nil {
		t.Fatal(err)
	}
	body := replaceVerifierReq{
		Username: c.username, SaltHex: hex.EncodeToString(newSalt),
		Iterations: c.iters, StoredKeyHex: hex.EncodeToString(newCred.StoredKey),
		ServerKeyHex: hex.EncodeToString(newCred.ServerKey),
	}

	// (1) No token → refused. Otherwise this route would be a weaker
	//     /auth/register rather than a stronger one.
	resp, _ := postJSON(t, c.srv.URL+"/auth/verifier", "", body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated replace must 401, got %d", resp.StatusCode)
	}

	// (2) With the device's own token → accepted.
	resp, _ = postJSON(t, c.srv.URL+"/auth/verifier", fr.TokenHex, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authed replace must 200, got %d", resp.StatusCode)
	}

	// (3) It actually TOOK. Asserting only the 200 above would pass against a
	//     handler that parsed the body and dropped it, which is the whole failure
	//     mode worth testing here. `/auth/scram/init` echoes the stored salt, so
	//     it is a direct read of the credential the server now holds.
	_, initBody := postJSON(t, c.srv.URL+"/auth/scram/init", "", scramInitReq{
		AccountHashHex: c.account, Username: c.username, ClientNonce: "cn-check",
	})
	var got scramInitResp
	if err := json.Unmarshal(initBody, &got); err != nil {
		t.Fatalf("scram/init body: %v", err)
	}
	if got.SaltHex != hex.EncodeToString(newSalt) {
		t.Fatalf("the stored verifier was not replaced: salt is %q, want %q",
			got.SaltHex, hex.EncodeToString(newSalt))
	}

	// …and a full handshake under the NEW secret completes, which the old one
	// could not.
	c.secret = newSecret
	c.salt = newSalt
	_ = c.scramEnroll(t, devID(0x02), "password")
}

// The replace route must not be a way to create an account's credential — that
// is /auth/register's job, and its first-write-only rule plus the capacity cap
// are what bound an unauthenticated flood.
func TestReplaceVerifier_UnregisteredAccountIsNotCreated(t *testing.T) {
	c := newEnv(t)
	c.register(t)
	fr := c.scramEnroll(t, devID(0x01), "password")

	// A well-formed body whose username is NOT this session's account.
	cred, _ := scram.MakeCredential(c.secret, c.salt, c.iters)
	resp, _ := postJSON(t, c.srv.URL+"/auth/verifier", fr.TokenHex, replaceVerifierReq{
		Username: strings.Repeat("99", 16), SaltHex: hex.EncodeToString(c.salt),
		Iterations: c.iters, StoredKeyHex: hex.EncodeToString(cred.StoredKey),
		ServerKeyHex: hex.EncodeToString(cred.ServerKey),
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a username that is not the session's account must 400, got %d", resp.StatusCode)
	}
}
