// SPDX-License-Identifier: AGPL-3.0

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
