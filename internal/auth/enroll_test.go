// SPDX-License-Identifier: AGPL-3.0-or-later

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

func TestTokens_RetiredDeviceTokenRejected(t *testing.T) {
	reg, ts, en := newEnroll()
	a, d := acct(5), dev(1)
	res, _ := en.Enroll(a, d, PathPassword)

	if err := reg.Retire(a, d); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Authenticate(res.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("retired device token still valid: %v", err)
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
