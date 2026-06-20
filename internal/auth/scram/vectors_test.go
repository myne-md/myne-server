// SPDX-License-Identifier: AGPL-3.0-or-later

package scram

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Cross-impl contract guard (the "Vector" test the CI gate runs). It asserts the
// Go SCRAM-SHA-256-PLUS implementation reproduces the committed golden vectors —
// the canonical bytes the Rust client must also match (gated by the MYND-420 R3
// review). Skips gracefully when the companion repo is absent.

type scramCase struct {
	VectorID      string `json:"vector_id"`
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

type scramFile struct {
	Schema string      `json:"schema"`
	Cases  []scramCase `json:"cases"`
}

func vectorsDir() string {
	if d := os.Getenv("MYNE_TEST_VECTORS_DIR"); d != "" {
		return d
	}
	return filepath.FromSlash("../../../../myne-test-vectors/vectors")
}

func dh(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestSCRAMVectors(t *testing.T) {
	path := filepath.Join(vectorsDir(), "scram-auth", "v0.1", "cases.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("[skip] scram-auth vectors absent at %s (%v)", path, err)
	}
	var f scramFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse cases.json: %v", err)
	}
	if f.Schema != "scram-auth" {
		t.Fatalf("unexpected schema %q", f.Schema)
	}
	if len(f.Cases) == 0 {
		t.Fatal("coverage guard: no scram-auth cases")
	}

	for _, c := range f.Cases {
		cred, err := MakeCredential(dh(t, c.SecretHex), dh(t, c.SaltHex), c.Iterations)
		if err != nil {
			t.Fatalf("%s: MakeCredential: %v", c.VectorID, err)
		}
		if !bytes.Equal(cred.StoredKey, dh(t, c.StoredKeyHex)) {
			t.Errorf("%s: StoredKey mismatch", c.VectorID)
		}
		if !bytes.Equal(cred.ServerKey, dh(t, c.ServerKeyHex)) {
			t.Errorf("%s: ServerKey mismatch", c.VectorID)
		}
		proof, serverSig, err := ClientProof(dh(t, c.SecretHex), cred, c.Username, c.ClientNonce, c.CombinedNonce, dh(t, c.CbindHex))
		if err != nil {
			t.Fatalf("%s: ClientProof: %v", c.VectorID, err)
		}
		if !bytes.Equal(proof, dh(t, c.ProofHex)) {
			t.Errorf("%s: client proof mismatch", c.VectorID)
		}
		if !bytes.Equal(serverSig, dh(t, c.ServerSigHex)) {
			t.Errorf("%s: server signature mismatch", c.VectorID)
		}
		// Round-trip: the server must accept the freshly computed proof.
		final := ClientFinalMessage(c.CombinedNonce, dh(t, c.CbindHex), proof)
		if _, err := VerifyClientFinal(cred, c.Username, c.ClientNonce, c.CombinedNonce, dh(t, c.CbindHex), final); err != nil {
			t.Errorf("%s: VerifyClientFinal: %v", c.VectorID, err)
		}
	}
	t.Logf("scram-auth: %d cases byte-exact", len(f.Cases))
}
