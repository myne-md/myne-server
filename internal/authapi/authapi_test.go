// SPDX-License-Identifier: AGPL-3.0

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
