// SPDX-License-Identifier: AGPL-3.0-only

// Package auth is the authentication seam. The bootstrap skeleton ships ONLY a
// deny-by-default authenticator: every request is rejected until a real mechanism
// is installed. SCRAM-SHA-256-PLUS + per-device tokens (MYND-420) plug into this
// interface without reshaping handlers (ledger SYNC-3). The skeleton MUST NOT ship
// an open/permissive authenticator.
package auth

import (
	"errors"

	"github.com/myne-md/myne-server/internal/ids"
)

// ErrUnauthenticated is returned when a request carries no valid session.
var ErrUnauthenticated = errors.New("auth: unauthenticated")

// ErrDeviceRevoked is returned when a request carries a token that resolves to a
// KNOWN device row which has been revoked/retired — as opposed to a token this
// server cannot resolve at all, which stays ErrUnauthenticated.
//
// The distinction exists because the two mean opposite things to a client
// (`server-protocol.md` §3.1, MYND-574 task 94). An unresolvable token might be
// expired, might be from a restarted server, might never have existed —
// re-authenticating fixes all three and none of them says anything about the
// account owner's intent. A retired registry row is a deliberate act performed
// from another client, and a client that cannot tell them apart cannot honour it:
// the web client treats revocation as terminal (it erases its local copy), while
// desktop and mobile keep parking and prompting to re-enrol.
//
// It is emitted only to the holder of a token this server itself issued, which
// is what keeps it from becoming a device-enumeration oracle. It carries no
// device id, no timestamp and no actor.
var ErrDeviceRevoked = errors.New("auth: device revoked")

// FailureCode maps an authentication failure to its wire `error_code`
// (`server-protocol.md` §3.1). Both outcomes are `401`; only the code differs,
// and the difference is what lets a client tell "your sign-in expired" from
// "the account owner removed this device from another client".
//
// It lives beside the errors rather than in each HTTP package because the spec
// clause is a MUST for **every** authed route, and three private copies of the
// same two-line mapping is how one route quietly keeps answering the old code.
// Anything that is not `ErrDeviceRevoked` — including a nil error reaching here
// by mistake — maps to `unauthenticated`, which is the safe direction: a client
// that hears `unauthenticated` re-authenticates, while one that hears
// `device_revoked` may erase its local copy.
func FailureCode(err error) string {
	if errors.Is(err, ErrDeviceRevoked) {
		return "device_revoked"
	}
	return "unauthenticated"
}

// Authenticator validates a per-device token and returns the bound account
// (account_number_hash). It is the single seam every push/pull/poke handler
// consumes (MYND-421/423); none re-derive auth.
type Authenticator interface {
	Authenticate(token ids.DeviceToken) (ids.AccountNumberHash, error)
}

// DenyAll is the deny-by-default Authenticator. It rejects every request until a
// real mechanism (MYND-420) is installed. This is the closed/dev-safe default —
// the bootstrap never ships an open authenticator.
type DenyAll struct{}

// Authenticate always rejects.
func (DenyAll) Authenticate(ids.DeviceToken) (ids.AccountNumberHash, error) {
	return ids.AccountNumberHash{}, ErrUnauthenticated
}

var _ Authenticator = DenyAll{}
