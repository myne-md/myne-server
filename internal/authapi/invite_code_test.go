// SPDX-License-Identifier: AGPL-3.0

package authapi

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/auth/scram"
)

// newInviteCodeEnv builds the same test client as newEnv, but with the invite gate on.
func newInviteCodeEnv(t *testing.T, code string) *testClient {
	t.Helper()
	reg := auth.NewRegistry()
	tokens := auth.NewTokenStore(reg)
	mux := http.NewServeMux()
	New(reg, tokens).WithInviteCode(code).Register(mux)
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

func (c *testClient) registerReqWith(t *testing.T, code string) registerReq {
	t.Helper()
	cred, err := scram.MakeCredential(c.secret, c.salt, c.iters)
	if err != nil {
		t.Fatal(err)
	}
	return registerReq{
		AccountHashHex: c.account,
		Username:       c.username,
		SaltHex:        hex.EncodeToString(c.salt),
		Iterations:     c.iters,
		StoredKeyHex:   hex.EncodeToString(cred.StoredKey),
		ServerKeyHex:   hex.EncodeToString(cred.ServerKey),
		InviteCode:     code,
	}
}

const testInviteCode = "correct-horse-battery-staple-0001"

func TestRegisterRequiresInviteCode(t *testing.T) {
	c := newInviteCodeEnv(t, testInviteCode)

	resp, body := postJSON(t, c.srv.URL+"/auth/register", "", c.registerReqWith(t, ""))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing code: status %d, want 403: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "invite_code_required") {
		t.Fatalf("missing code: body %q, want invite_code_required", body)
	}
}

func TestRegisterRejectsWrongInviteCode(t *testing.T) {
	c := newInviteCodeEnv(t, testInviteCode)

	resp, body := postJSON(t, c.srv.URL+"/auth/register", "", c.registerReqWith(t, "definitely-the-wrong-code-000000"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong code: status %d, want 403: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "invite_code_invalid") {
		t.Fatalf("wrong code: body %q, want invite_code_invalid", body)
	}
}

func TestRegisterAcceptsCorrectInviteCode(t *testing.T) {
	c := newInviteCodeEnv(t, testInviteCode)

	resp, body := postJSON(t, c.srv.URL+"/auth/register", "", c.registerReqWith(t, testInviteCode))
	if resp.StatusCode != 200 {
		t.Fatalf("correct code: status %d, want 200: %s", resp.StatusCode, body)
	}
}

// A device that joins an account which already exists must not need the code:
// the already-registered branch returns before the gate, and register_verifier
// treats 409 as idempotent success.
func TestExistingAccountNeedsNoInviteCode(t *testing.T) {
	c := newInviteCodeEnv(t, testInviteCode)

	resp, body := postJSON(t, c.srv.URL+"/auth/register", "", c.registerReqWith(t, testInviteCode))
	if resp.StatusCode != 200 {
		t.Fatalf("first register: status %d: %s", resp.StatusCode, body)
	}
	resp, body = postJSON(t, c.srv.URL+"/auth/register", "", c.registerReqWith(t, ""))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("re-register without code: status %d, want 409: %s", resp.StatusCode, body)
	}
}

// An ungated server ignores the field entirely: the old registration path is
// unchanged for self-host and every test that never sets a code.
func TestUngatedServerIgnoresInviteCode(t *testing.T) {
	c := newInviteCodeEnv(t, "")

	resp, body := postJSON(t, c.srv.URL+"/auth/register", "", c.registerReqWith(t, ""))
	if resp.StatusCode != 200 {
		t.Fatalf("ungated: status %d, want 200: %s", resp.StatusCode, body)
	}
}
