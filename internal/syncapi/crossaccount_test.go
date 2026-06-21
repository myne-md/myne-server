// SPDX-License-Identifier: AGPL-3.0-or-later

package syncapi

// Cross-account authorization over the real HTTP surface. The push/pull/blob API
// carries NO account parameter — the account is derived solely from the bearer token
// (sess.Account), so one account can never name another's vault. These tests drive
// two enrolled accounts against one shared store and assert tenant isolation: B's
// ciphertext is unreadable by A, versions do not bleed across vaults, a forged token
// authenticates to nothing, and an authed vault.meta write is token-scoped (cannot
// overwrite another account's meta). This is the load-bearing property of a
// zero-knowledge multi-tenant server.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// setupTwoAccounts enrolls two independent accounts (A, B) against one shared store +
// token store, each the founder of its own vault (first device → auto-approved token).
func setupTwoAccounts(t *testing.T) (srv *httptest.Server, tokenA, tokenB string, hashA, hashB ids.AccountNumberHash) {
	t.Helper()
	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)
	enroll := func(ab, db byte) (string, ids.AccountNumberHash) {
		var a ids.AccountNumberHash
		a[0] = ab
		var d ids.DeviceID
		d[0] = db
		res, err := en.Enroll(a, d, auth.PathPassword) // first device of an account → approved
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(res.Token), a
	}
	tokenA, hashA = enroll(0xA1, 0x01)
	tokenB, hashB = enroll(0xB2, 0x02)
	mux := http.NewServeMux()
	New(st, ts).Register(mux)
	return httptest.NewServer(mux), tokenA, tokenB, hashA, hashB
}

func TestCrossAccount_TokenCannotReachAnotherVault(t *testing.T) {
	srv, tokenA, tokenB, _, _ := setupTwoAccounts(t)
	defer srv.Close()

	id := strings.Repeat("cc", 16)
	nonceHex := strings.Repeat("dd", 24)
	secretB := []byte("account-B-secret-opaque-ciphertext")
	ctB := base64.StdEncoding.EncodeToString(secretB)
	prevZero := strings.Repeat("00", 32)
	headB := base64.StdEncoding.EncodeToString([]byte("B-head-record"))

	// B writes a blob (version 1) + a genesis head under its own token.
	pushB := `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonceHex +
		`","ciphertext_b64":"` + ctB + `"}],"new_head":{"prev_head_hash_hex":"` + prevZero + `","record_b64":"` + headB + `"}}`
	if resp, b := do(t, srv, http.MethodPost, "/sync/push", tokenB, pushB); resp.StatusCode != 200 {
		t.Fatalf("B push: %d %s", resp.StatusCode, b)
	}

	// (1) A reads B's blob id → 404 in A's empty namespace; B's bytes never returned.
	resp, body := do(t, srv, http.MethodGet, "/sync/blob?id="+id, tokenA, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("A reading B's blob: status %d, want 404", resp.StatusCode)
	}
	if bytes.Contains(body, secretB) || strings.Contains(string(body), ctB) {
		t.Fatal("B's ciphertext leaked to A via /sync/blob")
	}

	// (2) A pulls → sees none of B's metas and none of B's head.
	resp, body = do(t, srv, http.MethodGet, "/sync/pull?cursor=0", tokenA, "")
	if resp.StatusCode != 200 {
		t.Fatalf("A pull: %d %s", resp.StatusCode, body)
	}
	var plA pullResp
	if err := json.Unmarshal(body, &plA); err != nil {
		t.Fatal(err)
	}
	if len(plA.Metas) != 0 || plA.Head != nil {
		t.Fatalf("A's pull leaked B's state: %+v", plA)
	}

	// (3) A pushes its OWN blob at the same id, base 0 → succeeds at version 1,
	// independent of B's version (no CAS/version bleed across vault namespaces).
	secretA := []byte("account-A-own-ciphertext")
	ctA := base64.StdEncoding.EncodeToString(secretA)
	pushA := `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonceHex +
		`","ciphertext_b64":"` + ctA + `"}]}`
	resp, body = do(t, srv, http.MethodPost, "/sync/push", tokenA, pushA)
	if resp.StatusCode != 200 {
		t.Fatalf("A push own blob: %d %s", resp.StatusCode, body)
	}
	var prA pushResp
	if err := json.Unmarshal(body, &prA); err != nil {
		t.Fatal(err)
	}
	if len(prA.Results) != 1 || prA.Results[0].Version != 1 {
		t.Fatalf("A push version not independent of B: %+v", prA)
	}

	// (4) A reads id → its own bytes, never B's.
	resp, body = do(t, srv, http.MethodGet, "/sync/blob?id="+id, tokenA, "")
	if resp.StatusCode != 200 {
		t.Fatalf("A read own blob: %d %s", resp.StatusCode, body)
	}
	var br blobResp
	if err := json.Unmarshal(body, &br); err != nil {
		t.Fatal(err)
	}
	if br.CiphertextB64 != ctA || br.CiphertextB64 == ctB {
		t.Fatalf("A did not read exactly its own ciphertext: %+v", br)
	}

	// (5) B's vault is untouched by A's push (still version 1 with B's bytes).
	resp, body = do(t, srv, http.MethodGet, "/sync/blob?id="+id, tokenB, "")
	if resp.StatusCode != 200 {
		t.Fatalf("B read own blob: %d %s", resp.StatusCode, body)
	}
	var brB blobResp
	if err := json.Unmarshal(body, &brB); err != nil {
		t.Fatal(err)
	}
	if brB.CiphertextB64 != ctB || brB.Version != 1 {
		t.Fatalf("A's push corrupted B's vault: %+v", brB)
	}
}

func TestCrossAccount_ForgedTokenAuthenticatesToNothing(t *testing.T) {
	srv, tokenA, _, _, _ := setupTwoAccounts(t)
	defer srv.Close()
	id := strings.Repeat("ee", 16)
	nonceHex := strings.Repeat("dd", 24)
	ct := base64.StdEncoding.EncodeToString([]byte("x"))
	push := `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonceHex + `","ciphertext_b64":"` + ct + `"}]}`

	for _, tok := range []string{
		"",                       // no token → no Authorization header
		"deadbeef",               // random hex, unbound to any account
		strings.Repeat("00", 32), // all-zero 32-byte token
		tokenA + "ff",            // A's token with trailing bytes → not A's token
		"nothex",                 // non-hex → decode fails
	} {
		resp, _ := do(t, srv, http.MethodPost, "/sync/push", tok, push)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("forged token %q: status %d, want 401", tok, resp.StatusCode)
		}
	}
}

func TestCrossAccount_MetaPutIsTokenScoped(t *testing.T) {
	srv, tokenA, tokenB, _, hashB := setupTwoAccounts(t)
	defer srv.Close()

	metaB := []byte("B-original-meta-aead")
	if resp, _ := do(t, srv, http.MethodPut, "/vault.meta", tokenB, string(metaB)); resp.StatusCode != 200 {
		t.Fatal("B meta put failed")
	}
	// A uploads its own meta under its own token — must not touch B's.
	if resp, _ := do(t, srv, http.MethodPut, "/vault.meta", tokenA, "A-meta-overwrite-attempt"); resp.StatusCode != 200 {
		t.Fatal("A meta put failed")
	}
	// B's meta, fetched pre-auth by B's account hash, is unchanged.
	resp, body := do(t, srv, http.MethodGet, "/vault.meta?account="+hex.EncodeToString(hashB[:]), "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("B meta get: %d", resp.StatusCode)
	}
	if !bytes.Equal(body, metaB) {
		t.Fatalf("B's meta was overwritten by A: got %q, want %q", body, metaB)
	}
}
