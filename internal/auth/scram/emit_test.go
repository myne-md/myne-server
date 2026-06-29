// SPDX-License-Identifier: AGPL-3.0

package scram

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestEmitSCRAMVectors writes the canonical SCRAM-SHA-256-PLUS golden vectors to
// /tmp when MYNE_EMIT_VECTORS=1 (mirrors the Rust emit_*_for_paste pattern). Paste
// the output into myne-test-vectors/vectors/scram-auth/v0.1/cases.json. The Rust
// client must reproduce these byte-exact (gated by the MYND-420 R3 review).
func TestEmitSCRAMVectors(t *testing.T) {
	if os.Getenv("MYNE_EMIT_VECTORS") != "1" {
		t.Skip("set MYNE_EMIT_VECTORS=1 to emit")
	}
	type vector struct {
		VectorID      string `json:"vector_id"`
		CaseKind      string `json:"case_kind"`
		SecretHex     string `json:"input_secret_hex"`
		SaltHex       string `json:"input_salt_hex"`
		Iterations    int    `json:"input_iterations"`
		Username      string `json:"input_username"`
		ClientNonce   string `json:"input_client_nonce"`
		CombinedNonce string `json:"input_combined_nonce"`
		CbindHex      string `json:"input_cbind_data_hex"`
		StoredKeyHex  string `json:"expected_stored_key_hex"`
		ServerKeyHex  string `json:"expected_server_key_hex"`
		ProofHex      string `json:"expected_client_proof_hex"`
		ServerSigHex  string `json:"expected_server_signature_hex"`
	}

	mk := func(id string, secret, salt, cbind []byte) vector {
		cred, err := MakeCredential(secret, salt, 1)
		if err != nil {
			t.Fatal(err)
		}
		proof, serverSig, err := ClientProof(secret, cred, "MY-DEMO", "cn", "cnsn", cbind)
		if err != nil {
			t.Fatal(err)
		}
		return vector{
			VectorID:      id,
			CaseKind:      "scram_plus",
			SecretHex:     hex.EncodeToString(secret),
			SaltHex:       hex.EncodeToString(salt),
			Iterations:    1,
			Username:      "MY-DEMO",
			ClientNonce:   "cn",
			CombinedNonce: "cnsn",
			CbindHex:      hex.EncodeToString(cbind),
			StoredKeyHex:  hex.EncodeToString(cred.StoredKey),
			ServerKeyHex:  hex.EncodeToString(cred.ServerKey),
			ProofHex:      hex.EncodeToString(proof),
			ServerSigHex:  hex.EncodeToString(serverSig),
		}
	}

	rep := func(b byte, n int) []byte {
		out := make([]byte, n)
		for i := range out {
			out[i] = b
		}
		return out
	}

	doc := map[string]any{
		"schema":           "scram-auth",
		"protocol_version": "v0.1",
		"spec_section":     "server-protocol.md auth (MYND-420) · RFC 7677/5802/9266",
		"description":      "SCRAM-SHA-256-PLUS verifier + client proof + server signature (tls-exporter channel binding).",
		"cases": []vector{
			mk("scram-auth/v0.1/basic", rep(0xAB, 32), rep(0x11, 16), rep(0xCB, 32)),
			mk("scram-auth/v0.1/zero-secret", rep(0x00, 32), rep(0x22, 16), rep(0xCB, 32)),
			mk("scram-auth/v0.1/alt-cbind", rep(0xAB, 32), rep(0x11, 16), rep(0x5A, 32)),
		},
	}
	raw, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile("/tmp/scram_vectors.json", raw, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote /tmp/scram_vectors.json")
}
