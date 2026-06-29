// SPDX-License-Identifier: AGPL-3.0

// Package headid computes the vault-head identifier the blind server uses as the
// current-head pointer. head_id = SHA-256 over the opaque head record
// (head_mac_input || head_mac), matching the Rust client's compute_head_id
// (sync-protocol §3 / protocol/src/vault_head.rs). The server computes this over
// OPAQUE bytes only — it never parses the head and has no root_key, so it cannot
// forge one. This SHA-256 is the single structural crypto operation the bootstrap
// blind store performs; it is bit-identical to the Rust client and vector-gated
// against myne-test-vectors/vault-head/v0.1.
package headid

import "crypto/sha256"

// Len is the byte length of a head_id.
const Len = sha256.Size // 32

// Compute returns SHA-256 over the opaque head record.
func Compute(record []byte) [Len]byte {
	return sha256.Sum256(record)
}
