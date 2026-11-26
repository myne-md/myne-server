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

// newGatedEnv builds a testClient whose handler carries the operator enforcement gate.
func newGatedEnv(t *testing.T, frozen func(ids.AccountNumberHash) bool, maxDevices func(ids.AccountNumberHash) uint64) *testClient {
	t.Helper()
	reg := auth.NewRegistry()
	tokens := auth.NewTokenStore(reg)
	mux := http.NewServeMux()
	New(reg, tokens).WithAccountGate(frozen, maxDevices).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &testClient{
		srv:      srv,
		username: strings.Repeat("42", 16),
		account:  strings.Repeat("42", 16),
		secret:   bytes.Repeat([]byte{0xab}, 32),
		salt:     bytes.Repeat([]byte{0x11}, 16),
		iters:    1,
	}
}

// enrollFinalStatus runs init+final for dev and returns the FINAL HTTP status
// (non-fatal, unlike testClient.scramEnroll) so a gated (403) enroll can be asserted.
func enrollFinalStatus(t *testing.T, c *testClient, dev ids.DeviceID, path string) int {
	t.Helper()
	clientNonce := "cn-" + hex.EncodeToString(dev[:4])
	resp, body := postJSON(t, c.srv.URL+"/auth/scram/init", "", scramInitReq{
		AccountHashHex: c.account,
		Username:       c.username,
		ClientNonce:    clientNonce,
	})
	if resp.StatusCode != http.StatusOK {
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
	resp, _ = postJSON(t, c.srv.URL+"/auth/scram/final", "", scramFinalReq{
		HandshakeID: ir.HandshakeID,
		ClientFinal: clientFinal,
		DeviceIDHex: hex.EncodeToString(dev[:]),
		Path:        path,
	})
	return resp.StatusCode
}

// TestFrozen_BlocksEnroll: a frozen account cannot mint an enrollment token — the
// SCRAM proof succeeds but the gate refuses (403). Register itself is not gated.
func TestFrozen_BlocksEnroll(t *testing.T) {
	c := newGatedEnv(t, func(ids.AccountNumberHash) bool { return true }, nil)
	c.register(t)
	if s := enrollFinalStatus(t, c, devID(1), "password"); s != http.StatusForbidden {
		t.Fatalf("frozen enroll final status %d, want 403", s)
	}
}

// TestDeviceCap_BlocksBeyondCap: with an effective cap of 1, the first device
// enrolls (self-approves) and the second is refused (403 device_limit).
func TestDeviceCap_BlocksBeyondCap(t *testing.T) {
	c := newGatedEnv(t, nil, func(ids.AccountNumberHash) uint64 { return 1 })
	c.register(t)
	if s := enrollFinalStatus(t, c, devID(1), "password"); s != http.StatusOK {
		t.Fatalf("first device status %d, want 200 (within cap)", s)
	}
	if s := enrollFinalStatus(t, c, devID(2), "password"); s != http.StatusForbidden {
		t.Fatalf("second device status %d, want 403 (device cap)", s)
	}
}

// TestDeviceCap_ZeroIsUnlimited: cap 0 never blocks.
func TestDeviceCap_ZeroIsUnlimited(t *testing.T) {
	c := newGatedEnv(t, nil, func(ids.AccountNumberHash) uint64 { return 0 })
	c.register(t)
	if s := enrollFinalStatus(t, c, devID(1), "password"); s != http.StatusOK {
		t.Fatalf("cap 0 first device status %d, want 200", s)
	}
	// A second device with cap 0 is not blocked by the cap (it may still go pending,
	// which is a 200 with Approved:false — not a 403).
	if s := enrollFinalStatus(t, c, devID(2), "password"); s != http.StatusOK {
		t.Fatalf("cap 0 second device status %d, want 200 (unlimited)", s)
	}
}
