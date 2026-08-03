// SPDX-License-Identifier: AGPL-3.0

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

// The exporter parameters that GENERATE the channel-binding data the cases
// above take as given. `scram-auth` pins the arithmetic for a fixed
// `cbind_data` and says nothing about where those bytes come from; they come
// from `ExporterLabel` and `ExporterLen`, which used to exist only as two
// hand-written copies — one here, one in the Rust client — each documenting
// that the other must match it byte-for-byte, and neither checked. A
// divergence is not a degraded handshake: both sides derive different
// `cbind_data`, the client proof fails, and no -PLUS handshake can complete.

type exporterCase struct {
	VectorID  string `json:"vector_id"`
	CaseKind  string `json:"case_kind"`
	LabelHex  string `json:"expected_label_utf8_hex"`
	LengthVal int    `json:"expected_length"`
}

type exporterFile struct {
	Schema string         `json:"schema"`
	Cases  []exporterCase `json:"cases"`
}

func TestVectorTLSExporterParameters(t *testing.T) {
	path := filepath.Join(vectorsDir(), "tls-exporter", "v0.1", "cases.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("[skip] tls-exporter vectors absent at %s (%v)", path, err)
	}
	var f exporterFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse cases.json: %v", err)
	}
	if f.Schema != "tls-exporter" {
		t.Fatalf("unexpected schema %q", f.Schema)
	}
	if len(f.Cases) == 0 {
		t.Fatal("coverage guard: no tls-exporter cases")
	}
	for _, c := range f.Cases {
		if c.CaseKind != "parameters" {
			t.Fatalf("%s: unexpected case_kind %q", c.VectorID, c.CaseKind)
		}
		// Compare the label as BYTES, not as a string: that is how the TLS
		// stack compares it, and it is why the vector carries hex.
		if got, want := []byte(ExporterLabel), dh(t, c.LabelHex); !bytes.Equal(got, want) {
			t.Errorf("%s: ExporterLabel = %q (% x), want % x", c.VectorID, ExporterLabel, got, want)
		}
		if ExporterLen != c.LengthVal {
			t.Errorf("%s: ExporterLen = %d, want %d", c.VectorID, ExporterLen, c.LengthVal)
		}
	}
}
