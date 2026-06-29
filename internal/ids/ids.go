// SPDX-License-Identifier: AGPL-3.0

// Package ids holds the server's load-bearing identifier types. They are kept
// distinct on purpose (ledger SYNC-2): account_number_hash is the account /
// storage-namespace / rate-limit / quota key (the no-IP key, C4); device_id is
// the permanent version-vector actor and device-registry key (client-generated,
// never server-assigned, AS16); and the per-device token (see internal/auth) is
// a revocable bearer credential. Revoking a token MUST NOT touch a device_id.
package ids

const (
	// AccountNumberHashLen is the byte length of an account_number_hash.
	AccountNumberHashLen = 16
	// DeviceIDLen is the byte length of a device_id.
	DeviceIDLen = 16
	// BlobIDLen is the byte length of a blob id (a note uuid or an attachment-id
	// prefix the server uses purely as an opaque key).
	BlobIDLen = 16
)

// AccountNumberHash is the per-account key used for the storage namespace,
// rate-limiting, and quota. It is NEVER an IP. It is a fixed-size array so it can
// be used directly as a map key (comparable).
type AccountNumberHash [AccountNumberHashLen]byte

// DeviceID is the client-generated, permanent version-vector actor and registry
// key. The server never assigns or re-issues it.
type DeviceID [DeviceIDLen]byte

// BlobID keys an opaque ciphertext blob within a vault namespace. The server
// treats it as an opaque key and never derives meaning from it.
type BlobID [BlobIDLen]byte

// DeviceToken is the revocable per-device bearer credential issued at enrollment
// (managed by internal/auth, MYND-420). It is a distinct type from DeviceID on
// purpose: revoking a token MUST NOT touch the device's permanent DeviceID. The
// value is opaque and high-entropy.
type DeviceToken []byte
