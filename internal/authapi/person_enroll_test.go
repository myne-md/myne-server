// SPDX-License-Identifier: AGPL-3.0-only

package authapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The person plane's bootstrap exception (member-devices, myne-md/myne#852).
//
// A person account is an ordinary account in the /auth SCRAM namespace, keyed by
// person_id_hash (b2b.go's header), so it lands on exactly the same device gate a
// vault account does. The gate's rule is the one server-protocol.md §3.1 states:
// the first device on an account and any recovery-path device self-approve, a
// password-path device lands pending. The tests below are the person-plane twins
// of TestEnroll_RecoveryPathSelfApproves and
// TestEnroll_SecondPasswordDevice_PendingThenApproved in authapi_test.go, which
// stay the unchanged baseline for the vault plane: same gate, same two arms, a
// person-id-shaped account, and no way for the server to tell the two id kinds
// apart (it must not, and does not).
//
// Story 23 is the one that makes this load bearing: a member who has lost their
// only other device must not be gated behind a device they no longer hold, and
// nothing in the person plane can approve a pending device.

// personClient registers a person account (a plain 16-byte id) and returns the
// client plus the first device's token, so the account already HAS an approved
// device and the gate's `first device` arm cannot answer for the tests below.
// That is what makes them non-vacuous: with device 0x01 registered, an approval
// below can only come from the presented path.
func personClient(t *testing.T, e *b2bEnv, idHex string) (*testClient, string) {
	t.Helper()
	c, firstToken := e.account(t, idHex, 0x22)
	if firstToken == "" {
		t.Fatal("first person device must be approved with a token")
	}
	return c, firstToken
}

// approvedInRoster reads the account's device roster with an approved device's
// own token and reports whether targetIDHex is approved there. The roster is what
// makes a gate outcome a persisted fact rather than a response field.
func approvedInRoster(t *testing.T, c *testClient, token, targetIDHex string) bool {
	t.Helper()
	resp, body := sendJSON(t, http.MethodGet, c.srv.URL+"/auth/devices", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("devices status %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Devices []deviceWire `json:"devices"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	for _, d := range out.Devices {
		if d.DeviceIDHex == targetIDHex {
			return d.Approved
		}
	}
	t.Fatalf("device %s is absent from the roster", targetIDHex)
	return false
}

func TestPersonEnroll_PhraseSelfApproves(t *testing.T) {
	e := newB2BEnv(t)
	c, firstToken := personClient(t, e, b2bMember)

	// A second device presenting the phrase is approved on the spot: the phrase
	// is the person's root credential, so a pending gate on top of it adds
	// nothing while blocking a member whose only other device is gone.
	fr := c.scramEnroll(t, devID(0x02), "recovery")
	if !fr.Approved || fr.TokenHex == "" {
		t.Fatalf("person phrase enroll must self-approve with a token, got %+v", fr)
	}
	if fr.ServerSignatureB64 == "" {
		t.Fatalf("missing server signature (mutual auth)")
	}
	if !approvedInRoster(t, c, firstToken, devHex(0x02)) {
		t.Fatal("a phrase-approved device must show as approved in the roster")
	}

	// The token is the thing the acceptance criterion claims, so use it: it must
	// resolve on an authed route.
	resp, body := sendJSON(t, http.MethodGet, c.srv.URL+"/auth/devices", fr.TokenHex, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("phrase-issued token rejected on /auth/devices: %d %s", resp.StatusCode, body)
	}
}

func TestPersonEnroll_PasswordDeviceStaysPending(t *testing.T) {
	e := newB2BEnv(t)
	c, firstToken := personClient(t, e, b2bMember)

	// A person device that presents a password instead of the phrase is a
	// password-path device: unchanged, registered but not approved, no token.
	pending := c.scramEnroll(t, devID(0x02), "password")
	if pending.Approved || pending.TokenHex != "" {
		t.Fatalf("person password device must stay pending, got %+v", pending)
	}
	if pending.ServerSignatureB64 == "" {
		t.Fatalf("pending response must still carry the server signature")
	}
	if approvedInRoster(t, c, firstToken, devHex(0x02)) {
		t.Fatal("a pending person device must not be approved in the roster")
	}

	// An existing approved device of the SAME account is what releases it, exactly
	// as on the vault plane, and nothing in the person plane changes that.
	resp, body := postJSON(t, c.srv.URL+"/auth/devices/approve", firstToken, deviceActionReq{
		DeviceIDHex: devHex(0x02),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status %d: %s", resp.StatusCode, body)
	}
	if !approvedInRoster(t, c, firstToken, devHex(0x02)) {
		t.Fatal("approve must show the device as approved in the roster")
	}
	got := c.scramEnroll(t, devID(0x02), "password")
	if !got.Approved || got.TokenHex == "" {
		t.Fatalf("approved person device should now get a token, got %+v", got)
	}
}
