// SPDX-License-Identifier: AGPL-3.0

package headid

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// This is the cross-impl parity guard (the "Vector" test the CI vault-head gate
// runs via `go test -run Vector`). It proves the Go server's head_id computation
// is byte-identical to the Rust client by checking head_id = SHA-256(record),
// record = head_mac_input || head_mac, against the committed golden vectors. It
// skips gracefully when the companion repo is absent (mirrors the Rust runner).

type vhCase struct {
	CaseKind        string `json:"case_kind"`
	VectorID        string `json:"vector_id"`
	HeadMacInputHex string `json:"expected_head_mac_input_hex"`
	HeadMacHex      string `json:"expected_head_mac_hex"`
	HeadIDHex       string `json:"expected_head_id_hex"`
}

type vhFile struct {
	Schema string   `json:"schema"`
	Cases  []vhCase `json:"cases"`
}

func vectorsDir() string {
	if d := os.Getenv("MYNE_TEST_VECTORS_DIR"); d != "" {
		return d
	}
	// Local dev fallback: sibling companion checkout next to myne-server.
	return filepath.FromSlash("../../../myne-test-vectors/vectors")
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestVaultHeadIDVectors(t *testing.T) {
	path := filepath.Join(vectorsDir(), "vault-head", "v0.1", "cases.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("[skip] vault-head vectors absent at %s (%v) — set MYNE_TEST_VECTORS_DIR or check out the companion", path, err)
	}

	var f vhFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse cases.json: %v", err)
	}
	if f.Schema != "vault-head" {
		t.Fatalf("unexpected schema %q", f.Schema)
	}

	encodeSeen := 0
	for _, c := range f.Cases {
		if c.CaseKind != "encode" {
			continue
		}
		encodeSeen++
		record := append(append([]byte{}, mustHex(t, c.HeadMacInputHex)...), mustHex(t, c.HeadMacHex)...)
		got := Compute(record)
		want := mustHex(t, c.HeadIDHex)
		if !bytes.Equal(got[:], want) {
			t.Errorf("%s: head_id mismatch\n got  %x\n want %x", c.VectorID, got, want)
		}
	}

	if encodeSeen == 0 {
		t.Fatal("coverage guard: no encode cases found in vault-head vectors")
	}
	t.Logf("vault-head head_id parity: %d encode cases byte-exact vs Rust", encodeSeen)
}
