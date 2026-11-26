// SPDX-License-Identifier: AGPL-3.0-only

package authapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/myne-md/myne-server/internal/auth/scram"
	"github.com/myne-md/myne-server/internal/ids"
)

// The per-device SCRAM verifier (`decisions/protocol/0735`).
//
// The account credential derives from the person's recovery phrase, which is why a new
// device used to need the phrase to authenticate at all. These tests are the property
// that replaces it: a device authenticates with a verifier derived from ITS OWN secret,
// installed by a device that was already authenticated against the account.
//
// They are written against the REAL handshake rather than against the handler's return
// values, because the claim is "the device can log in", and a response field is not a
// login. The one thing they deliberately do NOT prove is that the secret never leaves the
// device: that is a client property, and it is proven on the client side.

// deviceClient is a device with its own secret, which never appears in any request body.
type deviceClient struct {
	secret []byte
	salt   []byte
	iters  int
}

func newDeviceClient(seed byte) deviceClient {
	return deviceClient{
		secret: bytes.Repeat([]byte{seed}, 32),
		salt:   bytes.Repeat([]byte{seed ^ 0x33}, 16),
		iters:  1,
	}
}

// install posts this device's verifier into the account, using `token` (an already
// authenticated device of that same account).
func (d deviceClient) install(t *testing.T, c *testClient, token string, dev ids.DeviceID) (*http.Response, []byte) {
	t.Helper()
	cred, err := scram.MakeCredential(d.secret, d.salt, d.iters)
	if err != nil {
		t.Fatal(err)
	}
	return postJSON(t, c.srv.URL+"/auth/devices/credential", token, deviceCredentialReq{
		DeviceIDHex:  hex.EncodeToString(dev[:]),
		Username:     deviceUsername(dev),
		SaltHex:      hex.EncodeToString(d.salt),
		Iterations:   d.iters,
		StoredKeyHex: hex.EncodeToString(cred.StoredKey),
		ServerKeyHex: hex.EncodeToString(cred.ServerKey),
	})
}

// enroll runs the full handshake as THIS device, presenting its own username and secret.
func (d deviceClient) enroll(t *testing.T, c *testClient, dev ids.DeviceID) scramFinalResp {
	t.Helper()
	username := deviceUsername(dev)
	clientNonce := "cn-" + hex.EncodeToString(dev[:4])
	resp, body := postJSON(t, c.srv.URL+"/auth/scram/init", "", scramInitReq{
		AccountHashHex: c.account,
		Username:       username,
		ClientNonce:    clientNonce,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("init status %d: %s", resp.StatusCode, body)
	}
	var ir scramInitResp
	if err := json.Unmarshal(body, &ir); err != nil {
		t.Fatal(err)
	}
	// The server must serve THIS device's salt, not the account's: handing back the
	// account salt would make the client derive a proof the device credential cannot
	// satisfy, and the symptom would look like a wrong password.
	if !bytes.Equal(mustHex(t, ir.SaltHex), d.salt) {
		t.Fatalf("init served salt %s, want this device's own %s",
			ir.SaltHex, hex.EncodeToString(d.salt))
	}
	cred, err := scram.MakeCredential(d.secret, d.salt, d.iters)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := scram.ClientProof(d.secret, cred, username, clientNonce, ir.CombinedNonce, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, body = postJSON(t, c.srv.URL+"/auth/scram/final", "", scramFinalReq{
		HandshakeID: ir.HandshakeID,
		ClientFinal: scram.ClientFinalMessage(ir.CombinedNonce, nil, proof),
		DeviceIDHex: hex.EncodeToString(dev[:]),
		Path:        "password",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status %d: %s", resp.StatusCode, body)
	}
	var fr scramFinalResp
	if err := json.Unmarshal(body, &fr); err != nil {
		t.Fatal(err)
	}
	return fr
}

func mustBytes(t *testing.T, s string) [16]byte {
	t.Helper()
	var out [16]byte
	copy(out[:], mustHex(t, s))
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A device whose credential an existing device installed logs in, and the token it
// receives resolves on an authed route. That is the whole promise: no phrase on this
// device, ever.
func TestDeviceCredential_InstalledByExistingDeviceLogsIn(t *testing.T) {
	e := newB2BEnv(t)
	c, firstToken := personClient(t, e, b2bMember)
	dev := devID(0x05)
	d := newDeviceClient(0x51)

	resp, body := d.install(t, c, firstToken, dev)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("install status %d: %s", resp.StatusCode, body)
	}

	fr := d.enroll(t, c, dev)
	if !fr.Approved || fr.TokenHex == "" {
		t.Fatalf("a device with an installed credential must be admitted with a token, got %+v", fr)
	}
	if fr.ServerSignatureB64 == "" {
		t.Fatal("missing server signature (mutual auth)")
	}
	// The install IS the approval, so the roster must already say so.
	if !approvedInRoster(t, c, firstToken, devHex(0x05)) {
		t.Fatal("the install must leave the device approved in the roster")
	}
	check, checkBody := sendJSON(t, http.MethodGet, c.srv.URL+"/auth/devices", fr.TokenHex, nil)
	if check.StatusCode != http.StatusOK {
		t.Fatalf("device-credential token rejected on /auth/devices: %d %s", check.StatusCode, checkBody)
	}
}

// Two devices admitting the same new device at once must not race into two credentials,
// and a retry after a dropped response must not fail. Same verifier is idempotent,
// different verifier is a 409 the caller can report rather than a silent overwrite.
func TestDeviceCredential_InstallIsIdempotentAndRefusesASecondVerifier(t *testing.T) {
	e := newB2BEnv(t)
	c, firstToken := personClient(t, e, b2bMember)
	dev := devID(0x06)
	d := newDeviceClient(0x61)

	if resp, body := d.install(t, c, firstToken, dev); resp.StatusCode != http.StatusOK {
		t.Fatalf("first install status %d: %s", resp.StatusCode, body)
	}
	resp, body := d.install(t, c, firstToken, dev)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a repeated install of the SAME verifier must be a no-op, got %d: %s", resp.StatusCode, body)
	}
	var out map[string]bool
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if !out["existing"] {
		t.Fatalf("a repeat must say the credential already existed, got %s", body)
	}

	other := newDeviceClient(0x62)
	resp, body = other.install(t, c, firstToken, dev)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("a DIFFERENT verifier for the same device must 409, got %d: %s", resp.StatusCode, body)
	}
}

// Revocation has to reach the VERIFIER, not only the token. Retiring the registry row
// refuses the token; a device that can still run the handshake simply mints a new one, so
// "removed" would have meant "log in again".
func TestDeviceCredential_RevokeRemovesTheVerifier(t *testing.T) {
	e := newB2BEnv(t)
	c, firstToken := personClient(t, e, b2bMember)
	dev := devID(0x07)
	d := newDeviceClient(0x71)
	if resp, body := d.install(t, c, firstToken, dev); resp.StatusCode != http.StatusOK {
		t.Fatalf("install status %d: %s", resp.StatusCode, body)
	}
	if fr := d.enroll(t, c, dev); !fr.Approved {
		t.Fatal("the installed device must log in before the revoke")
	}

	resp, body := postJSON(t, c.srv.URL+"/auth/devices/revoke", firstToken, deviceActionReq{
		DeviceIDHex: devHex(0x07),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status %d: %s", resp.StatusCode, body)
	}

	// The handshake itself must now fail: the credential is gone, so init answers the
	// same 401 an unknown account does (no enumeration signal).
	initResp, initBody := postJSON(t, c.srv.URL+"/auth/scram/init", "", scramInitReq{
		AccountHashHex: c.account,
		Username:       deviceUsername(dev),
		ClientNonce:    "cn-after-revoke",
	})
	if initResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a revoked device must not begin a handshake, got %d: %s", initResp.StatusCode, initBody)
	}

	// And the ACCOUNT credential is untouched: the owner still logs in with the phrase.
	if fr := c.scramEnroll(t, devID(0x08), "recovery"); !fr.Approved {
		t.Fatal("revoking a device credential must not disturb the account credential")
	}
}

// A credential belongs to one device of one account. Installing for a username that is
// not the canonical `dev:<device id>` form is refused, so the two namespaces (an account
// id and a device id are both 16 bytes) cannot be confused for one another.
func TestDeviceCredential_RefusesAForeignUsername(t *testing.T) {
	e := newB2BEnv(t)
	c, firstToken := personClient(t, e, b2bMember)
	d := newDeviceClient(0x91)
	cred, err := scram.MakeCredential(d.secret, d.salt, d.iters)
	if err != nil {
		t.Fatal(err)
	}
	for _, username := range []string{
		canonicalUsername(mustBytes(t, c.account)),                       // the account's own username
		deviceUsername(devID(0x0a)),                                      // a DIFFERENT device's username
		"dev:" + hex.EncodeToString(bytes.Repeat([]byte{0x09}, 16))[:30], // truncated
		"DEV:" + devHex(0x09),                                            // same device, wrong case on the prefix
	} {
		resp, body := postJSON(t, c.srv.URL+"/auth/devices/credential", firstToken, deviceCredentialReq{
			DeviceIDHex:  devHex(0x09),
			Username:     username,
			SaltHex:      hex.EncodeToString(d.salt),
			Iterations:   d.iters,
			StoredKeyHex: hex.EncodeToString(cred.StoredKey),
			ServerKeyHex: hex.EncodeToString(cred.ServerKey),
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("username %q must be refused, got %d: %s", username, resp.StatusCode, body)
		}
	}
}

// The persisted shape round-trips, and an ABSENT snapshot (an auth.json written before
// this existed) reads as "no device has its own verifier" rather than failing.
func TestDeviceCredential_SnapshotRoundTrip(t *testing.T) {
	e := newB2BEnv(t)
	c, firstToken := personClient(t, e, b2bMember)
	d := newDeviceClient(0xb1)

	h := e.h
	// Install AFTER capturing the handler, so the snapshot below describes a state the
	// route really wrote rather than one a test constructed.
	dev := devID(0x0b)
	if resp, body := d.install(t, c, firstToken, dev); resp.StatusCode != http.StatusOK {
		t.Fatalf("install status %d: %s", resp.StatusCode, body)
	}
	snap := h.DeviceCredSnapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot holds %d device credentials, want 1", len(snap))
	}
	if snap[0].Username != deviceUsername(dev) {
		t.Fatalf("snapshot username %q, want %q", snap[0].Username, deviceUsername(dev))
	}

	h.LoadDeviceCreds(nil)
	if got := h.DeviceCredSnapshot(); len(got) != 0 {
		t.Fatalf("an absent snapshot must read as empty, got %d", len(got))
	}
	h.LoadDeviceCreds(snap)
	if got := h.DeviceCredSnapshot(); len(got) != 1 {
		t.Fatalf("reloaded %d device credentials, want 1", len(got))
	}
	// And the reloaded verifier still authenticates, which is what makes the snapshot a
	// credential rather than a shape.
	if fr := d.enroll(t, c, dev); !fr.Approved {
		t.Fatal("a reloaded device credential must still log in")
	}
}
