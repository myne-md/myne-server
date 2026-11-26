// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"errors"

	"github.com/myne-md/myne-server/internal/ids"
)

// EnrollPath is how a device proved account ownership.
type EnrollPath int

const (
	// PathPassword: {account number + password} → root_key. A new password-path
	// device requires approval from an existing unlocked device (unless it is the
	// first device on the account).
	PathPassword EnrollPath = iota
	// PathRecovery: {account number + 24-word phrase} → root_key. Self-approves
	// (the bootstrap exception, so a sole-device-loss user can recover). This is an
	// honestly-accepted hole: the phrase is full account takeover.
	PathRecovery
)

// Enroll errors.
var (
	ErrPendingApproval = errors.New("auth: device pending approval by an existing device")
)

// Enrollment ties account-ownership proof (SCRAM, verified by the caller) to the
// device-approval gate + token issuance. It owns no crypto — SCRAM verification is
// done in package scram before Enroll is called.
type Enrollment struct {
	reg    *Registry
	tokens *TokenStore
}

// NewEnrollment wires the device registry + token store.
func NewEnrollment(reg *Registry, tokens *TokenStore) *Enrollment {
	return &Enrollment{reg: reg, tokens: tokens}
}

// EnrollResult reports the gate outcome.
type EnrollResult struct {
	Approved bool
	Token    ids.DeviceToken // non-nil only when Approved
}

// Enroll applies the device-approval gate (ledger SYNC-9, server-side authz) and,
// when approved, issues a per-device token. SCRAM account-ownership proof MUST have
// already succeeded for `account` (the caller verifies it via package scram).
//
// Gate (design Q8):
//   - first device on the account  → self-approve (onboarding not deadlocked)
//   - PathRecovery (24-word)        → self-approve (bootstrap exception)
//   - PathPassword w/ existing devs → pending; an existing unlocked device must
//     Approve() it before a token is issued (closes "password leaked, device not
//     stolen")
func (e *Enrollment) Enroll(account ids.AccountNumberHash, dev ids.DeviceID, path EnrollPath) (EnrollResult, error) {
	first := !e.reg.hasAnyDevice(account)

	approved := first || path == PathRecovery
	if err := e.reg.register(account, dev, approved); err != nil {
		return EnrollResult{}, err
	}
	if !approved {
		// Pending: registered but no token until an existing device approves.
		return EnrollResult{Approved: false}, ErrPendingApproval
	}
	tok, err := e.tokens.Issue(account, dev)
	if err != nil {
		return EnrollResult{}, err
	}
	return EnrollResult{Approved: true, Token: tok}, nil
}

// CompleteApproval issues a token for a device that was pending and has since been
// approved by an existing unlocked device.
func (e *Enrollment) CompleteApproval(account ids.AccountNumberHash, dev ids.DeviceID) (ids.DeviceToken, error) {
	rec, ok := e.reg.Get(account, dev)
	if !ok {
		return nil, ErrDeviceNotFound
	}
	if !rec.Approved || rec.Retired {
		return nil, ErrPendingApproval
	}
	return e.tokens.Issue(account, dev)
}
