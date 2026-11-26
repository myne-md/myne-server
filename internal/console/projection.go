// SPDX-License-Identifier: AGPL-3.0-only

// Package console is the READ-ONLY projection of operator enforcement state that
// both operator surfaces render: the Unix-socket admin API (internal/adminapi) and
// the browser operator panel (internal/panel). It is the single place a field is
// turned into a row, so the two surfaces cannot drift and the aggregate-only
// invariant (MYND-440) has one enforcement point rather than two.
//
// This package contains NO write path. That is the point of the split: the panel
// depends on console alone, so it cannot name a write handler even by mistake, and
// its read-only-ness is a property of the import graph rather than a check inside a
// handler. Enforcement writes live in internal/adminapi and internal/accounts.
//
// Posture (TB5): server-side PLAINTEXT operator metadata of the same class as the
// device count and stored-byte size the server already holds. Never user content,
// never a new observation channel: no request history, no last-seen wall-clocks,
// no per-account time series.
package console

import (
	"encoding/hex"

	"github.com/myne-md/myne-server/internal/accounts"
	"github.com/myne-md/myne-server/internal/ids"
)

// AccountView is the merged live-stats + operator-policy projection of one account.
//
// It carries NO timestamp / activity / request-history field, and the struct tags
// are the admin API's wire contract: the two surfaces must render the same row, so
// these names are load-bearing for internal/adminapi's JSON output and its
// aggregate-only denylist test.
type AccountView struct {
	AccountHash        string `json:"account_hash"`
	StoredBytes        uint64 `json:"stored_bytes"`
	DeviceCount        uint64 `json:"device_count"`
	Frozen             bool   `json:"frozen"`
	QuotaOverrideBytes uint64 `json:"quota_override_bytes,omitempty"`
	MaxDevicesOverride uint64 `json:"max_devices_override,omitempty"`
}

// StatsView is the deployment-wide aggregate.
type StatsView struct {
	TotalAccounts    uint64 `json:"total_accounts"`
	TotalStoredBytes uint64 `json:"total_stored_bytes"`
	MaxAccounts      uint64 `json:"max_accounts"` // 0 = unlimited

	// FrozenAccounts is a Go-side count for the panel's summary row. It is
	// deliberately NOT on the wire: the admin API's /admin/stats body is a published
	// contract, and nothing asked for a fourth field on it. The panel reads this
	// field directly, so no wire value moves.
	FrozenAccounts uint64 `json:"-"`
}

// Projection reads live enforcement state on demand. It holds no cache and no state
// of its own: every call goes to the injected closures and the policy store, so two
// page loads against an unchanged deployment are identical and there is nothing to
// accumulate. All deps may be nil, in which case the read side reports zeros.
type Projection struct {
	listAccts   func() []ids.AccountNumberHash
	usedBytes   func(ids.AccountNumberHash) uint64 // stored ciphertext bytes (blobs + attachments; the AS17 total)
	deviceCount func(ids.AccountNumberHash) uint64
	policy      *accounts.Store
	maxAccounts uint64 // 0 = unlimited
}

// NewProjection builds the shared read projection. Dependencies are injected as
// closures plus the accounts store so neither operator surface pulls in server
// internals.
func NewProjection(listAccts func() []ids.AccountNumberHash, usedBytes, deviceCount func(ids.AccountNumberHash) uint64, policy *accounts.Store, maxAccounts uint64) *Projection {
	return &Projection{
		listAccts:   listAccts,
		usedBytes:   usedBytes,
		deviceCount: deviceCount,
		policy:      policy,
		maxAccounts: maxAccounts,
	}
}

// Account projects one account. A malformed or absent hash is not an error here:
// callers parse before reaching this.
func (p *Projection) Account(a ids.AccountNumberHash) AccountView {
	v := AccountView{AccountHash: hex.EncodeToString(a[:])}
	if p.usedBytes != nil {
		v.StoredBytes = p.usedBytes(a)
	}
	if p.deviceCount != nil {
		v.DeviceCount = p.deviceCount(a)
	}
	if p.policy != nil {
		pol := p.policy.Get(a)
		v.Frozen = pol.Frozen
		v.QuotaOverrideBytes = pol.QuotaOverrideBytes
		v.MaxDevicesOverride = pol.MaxDevicesOverride
	}
	return v
}

// Accounts projects every account the store can enumerate. A backend that cannot
// enumerate (the in-memory dev store) yields an empty slice, not an error, so an
// operator on that backend reads "no accounts" rather than a failure.
func (p *Projection) Accounts() []AccountView {
	var accts []ids.AccountNumberHash
	if p.listAccts != nil {
		accts = p.listAccts()
	}
	out := make([]AccountView, 0, len(accts))
	for _, a := range accts {
		out = append(out, p.Account(a))
	}
	return out
}

// Stats aggregates the deployment. FrozenAccounts is counted from the same policy
// store Account reads, so the summary can never disagree with the rows below it.
func (p *Projection) Stats() StatsView { return StatsOf(p.Accounts(), p.maxAccounts) }

// MaxAccounts is the configured account ceiling (0 = unlimited), exposed so a caller
// that already holds the rows can build the aggregate without enumerating a second
// time.
func (p *Projection) MaxAccounts() uint64 { return p.maxAccounts }

// StatsOf aggregates an ALREADY-PROJECTED row set. A caller holding the rows builds
// the summary from them here rather than calling Stats() and paying for a second
// full enumeration: the panel does exactly that, and on an unauthenticated listener a
// per-account walk is a cost an outsider can drive.
func StatsOf(views []AccountView, maxAccounts uint64) StatsView {
	s := StatsView{TotalAccounts: uint64(len(views)), MaxAccounts: maxAccounts}
	for _, v := range views {
		s.TotalStoredBytes += v.StoredBytes
		if v.Frozen {
			s.FrozenAccounts++
		}
	}
	return s
}
