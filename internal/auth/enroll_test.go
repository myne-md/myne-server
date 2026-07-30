// SPDX-License-Identifier: AGPL-3.0

package auth

import (
	"errors"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func acct(b byte) ids.AccountNumberHash {
	var a ids.AccountNumberHash
	for i := range a {
		a[i] = b
	}
	return a
}

func dev(b byte) ids.DeviceID {
	var d ids.DeviceID
	for i := range d {
		d[i] = b
	}
	return d
}

func newEnroll() (*Registry, *TokenStore, *Enrollment) {
	reg := NewRegistry()
	ts := NewTokenStore(reg)
	return reg, ts, NewEnrollment(reg, ts)
}

func TestEnroll_FirstDeviceSelfApproves(t *testing.T) {
	_, ts, en := newEnroll()
	a, d := acct(1), dev(1)
	res, err := en.Enroll(a, d, PathPassword)
	if err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	if !res.Approved || len(res.Token) != TokenLen {
		t.Fatalf("first device not approved with a token: %+v", res)
	}
	// The issued token authenticates to the account.
	got, err := ts.Authenticate(res.Token)
	if err != nil || got != a {
		t.Fatalf("token auth = (%x, %v), want account %x", got, err, a)
	}
}

func TestEnroll_PasswordPathSecondDevicePending(t *testing.T) {
	reg, ts, en := newEnroll()
	a := acct(2)
	if _, err := en.Enroll(a, dev(1), PathPassword); err != nil {
		t.Fatal(err)
	}
	// Second password-path device: pending, no token.
	res, err := en.Enroll(a, dev(2), PathPassword)
	if !errors.Is(err, ErrPendingApproval) {
		t.Fatalf("second device: %v, want ErrPendingApproval", err)
	}
	if res.Approved || res.Token != nil {
		t.Fatalf("pending device got a token: %+v", res)
	}
	// An existing unlocked device approves it → token issues.
	if err := reg.Approve(a, dev(2)); err != nil {
		t.Fatal(err)
	}
	tok, err := en.CompleteApproval(a, dev(2))
	if err != nil || len(tok) != TokenLen {
		t.Fatalf("CompleteApproval = (%x, %v)", tok, err)
	}
	if _, err := ts.Authenticate(tok); err != nil {
		t.Fatalf("approved device token rejected: %v", err)
	}
}

func TestEnroll_RecoveryPathSelfApproves(t *testing.T) {
	_, _, en := newEnroll()
	a := acct(3)
	if _, err := en.Enroll(a, dev(1), PathPassword); err != nil {
		t.Fatal(err)
	}
	// A recovery-path device self-approves even with existing devices (bootstrap
	// exception — sole-device-loss recovery).
	res, err := en.Enroll(a, dev(9), PathRecovery)
	if err != nil {
		t.Fatalf("recovery enroll: %v", err)
	}
	if !res.Approved || res.Token == nil {
		t.Fatalf("recovery path not self-approved: %+v", res)
	}
}

func TestTokens_RevokeStopsAuthButKeepsDeviceID(t *testing.T) {
	reg, ts, en := newEnroll()
	a, d := acct(4), dev(1)
	res, _ := en.Enroll(a, d, PathPassword)

	ts.Revoke(res.Token)
	if _, err := ts.Authenticate(res.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked token still valid: %v", err)
	}
	// The device_id survives revocation (revoke is availability-only, not a wipe).
	if _, ok := reg.Get(a, d); !ok {
		t.Fatal("device_id removed by token revocation (should survive)")
	}
}

// A retired device's token is REJECTED, and since MYND-574 task 94 it is
// rejected with its own error. Both halves are asserted: the rejection is the
// security property (it must never fail open), and the specific error is what a
// client needs in order to tell a deliberate removal from an expired session.
func TestTokens_RetiredDeviceTokenRejected(t *testing.T) {
	reg, ts, en := newEnroll()
	a, d := acct(5), dev(1)
	res, _ := en.Enroll(a, d, PathPassword)

	if err := reg.Retire(a, d); err != nil {
		t.Fatal(err)
	}
	_, err := ts.Authenticate(res.Token)
	if err == nil {
		t.Fatal("retired device token still valid")
	}
	if !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("want ErrDeviceRevoked, got %v", err)
	}
}

// The pairing that gives the code its meaning: an UNRESOLVABLE token stays
// `ErrUnauthenticated`. The server genuinely does not know whether it was
// revoked, expired, or never existed — and claiming "revoked" from a guess would
// make a web client erase its local copy on any stale token. It is also what
// keeps the code from being a device-enumeration oracle: only the holder of a
// token this server issued can ever see it.
func TestTokens_UnknownTokenIsUnauthenticatedNotRevoked(t *testing.T) {
	_, ts, _ := newEnroll()
	var bogus ids.DeviceToken = make([]byte, TokenLen)
	bogus[0] = 0xAB
	_, err := ts.Authenticate(bogus)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("want ErrUnauthenticated for an unknown token, got %v", err)
	}
	if errors.Is(err, ErrDeviceRevoked) {
		t.Fatal("an unknown token must never be reported as revoked")
	}
}

// Revocation must survive a restart AS revocation (task 94).
//
// The code is reachable only because a retired device's token binding is kept
// rather than deleted. That retention has to hold through persistence too: a
// snapshot that pruned bindings for retired devices — an obviously reasonable
// tidy-up — would leave auth still failing closed while silently downgrading the
// answer to `unauthenticated` on the next boot. Nothing else would notice, which
// is exactly why it is pinned here rather than left to the shape of the code.
func TestTokens_RevocationSurvivesAPersistenceRoundTrip(t *testing.T) {
	reg, ts, en := newEnroll()
	a, d := acct(7), dev(1)
	res, _ := en.Enroll(a, d, PathPassword)
	if err := reg.Retire(a, d); err != nil {
		t.Fatal(err)
	}

	reg2 := NewRegistry()
	reg2.LoadDevices(reg.DeviceSnapshot())
	ts2 := NewTokenStore(reg2)
	ts2.LoadTokens(ts.TokenSnapshot())

	if _, err := ts2.Authenticate(res.Token); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("want ErrDeviceRevoked after a restart, got %v", err)
	}
}

func TestRegistry_TouchActivityIsMonotone(t *testing.T) {
	reg, _, en := newEnroll()
	a, d := acct(6), dev(1)
	if _, err := en.Enroll(a, d, PathPassword); err != nil {
		t.Fatal(err)
	}
	_ = reg.TouchActivity(a, d, 5)
	_ = reg.TouchActivity(a, d, 3) // older marker ignored
	rec, _ := reg.Get(a, d)
	if rec.LastActivity != 5 {
		t.Fatalf("LastActivity = %d, want 5 (monotone, older ignored)", rec.LastActivity)
	}
}

// TestRegistry_ListOrderIsDeterministic pins MYND-588: List must return the
// roster sorted by DeviceID, identically on every call. Go randomises map
// iteration, so an unsorted List reshuffles GET /auth/devices between calls —
// visible as rows teleporting under the cursor, and a wrong-device-removal
// hazard on the per-row Remove button. Devices are inserted out of ID order and
// the sorted order is asserted over many calls; without the sort at least one
// call almost certainly diverges.
func TestRegistry_ListOrderIsDeterministic(t *testing.T) {
	reg := NewRegistry()
	a := acct(7)
	for _, b := range []byte{3, 1, 2} {
		if err := reg.register(a, dev(b), true); err != nil {
			t.Fatalf("register %d: %v", b, err)
		}
	}
	want := []ids.DeviceID{dev(1), dev(2), dev(3)}
	for call := 0; call < 32; call++ {
		got := reg.List(a)
		if len(got) != len(want) {
			t.Fatalf("call %d: len = %d, want %d", call, len(got), len(want))
		}
		for i := range want {
			if got[i].DeviceID != want[i] {
				t.Fatalf("call %d: order[%d] = %x, want %x", call, i, got[i].DeviceID, want[i])
			}
		}
	}
}
