// SPDX-License-Identifier: AGPL-3.0

package attachments

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
)

// The person-session vault selector on the attachment routes (myne-md/myne#911).
//
// A person session carries no vault, so a person-born vault's attachment bytes
// have to name one or they land in the person's own namespace, where no other
// device can fetch them: every request is scoped to the account that stored the
// bytes. The selector is the same `?account=` the sync routes take, and the same
// membership table decides it. These cases pin all three answers, because the
// dangerous one is the middle: an unbound caller must be refused rather than
// served from its own namespace.
func setupSelector(
	t *testing.T,
	bound func(vault, person ids.AccountNumberHash) (bool, bool),
) (*httptest.Server, string, *Store, ids.AccountNumberHash) {
	t.Helper()
	st := NewStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)
	var person ids.AccountNumberHash
	person[0] = 0x42
	var d ids.DeviceID
	d[0] = 1
	res, err := en.Enroll(person, d, auth.PathPassword)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(st, ts).WithVaultSelector(bound).Register(mux)
	return httptest.NewServer(mux), hex.EncodeToString(res.Token), st, person
}

func vaultHash() ids.AccountNumberHash {
	var v ids.AccountNumberHash
	v[0] = 0x77
	return v
}

func boundFor(
	want ids.AccountNumberHash,
	person ids.AccountNumberHash,
) func(vault, person ids.AccountNumberHash) (bool, bool) {
	return func(v, p ids.AccountNumberHash) (bool, bool) {
		return v == want && p == person, true
	}
}

func putChunk(t *testing.T, srv *httptest.Server, token, query, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(
		http.MethodPut,
		srv.URL+"/attachments/"+strings.Repeat("ab", 32)+query,
		strings.NewReader(body),
	)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestAttachmentSelector_UnboundCallerIsRefused(t *testing.T) {
	srv, token, st, _ := setupSelector(t, func(_, _ ids.AccountNumberHash) (bool, bool) {
		return false, true
	})
	defer srv.Close()

	resp := putChunk(t, srv, token, "?account="+strings.Repeat("77", 16)+"&offset=0&total=2", "hi")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an unbound selector must be 403, got %d", resp.StatusCode)
	}
	var personAccount ids.AccountNumberHash
	personAccount[0] = 0x42
	if n, _ := st.UploadedLen(personAccount, AttachmentID{}); n != 0 {
		t.Fatalf("nothing may be written to the caller's own namespace on a refusal")
	}
}

func TestAttachmentSelector_MalformedSelectorIsABadRequest(t *testing.T) {
	srv, token, _, _ := setupSelector(t, func(_, _ ids.AccountNumberHash) (bool, bool) {
		return true, true
	})
	defer srv.Close()

	resp := putChunk(t, srv, token, "?account=nothex&offset=0&total=2", "hi")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a malformed selector must be 400, got %d", resp.StatusCode)
	}
}

func TestAttachmentSelector_BoundCallerStoresUnderTheVault(t *testing.T) {
	vault := vaultHash()
	var person ids.AccountNumberHash
	person[0] = 0x42
	srv, token, st, _ := setupSelector(t, boundFor(vault, person))
	defer srv.Close()

	resp := putChunk(t, srv, token, "?account="+hex.EncodeToString(vault[:])+"&offset=0&total=2", "hi")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a bound selector must be accepted, got %d", resp.StatusCode)
	}
	var id AttachmentID
	for i := range id {
		id[i] = 0xab
	}
	if n, known := st.UploadedLen(vault, id); !known || n != 2 {
		t.Fatalf("the bytes must live under the VAULT namespace: known=%v n=%d", known, n)
	}
	if n, known := st.UploadedLen(person, id); known && n != 0 {
		t.Fatalf("the bytes must not also land under the person's own namespace")
	}
}

// A session with no parameter keeps the exact pre-selector behaviour: its own
// account, and the selector seam plays no part.
func TestAttachmentSelector_NoParameterIsUnchanged(t *testing.T) {
	srv, token, st, person := setupSelector(t, func(_, _ ids.AccountNumberHash) (bool, bool) {
		t.Fatal("the binding table must not be consulted when no vault is named")
		return false, false
	})
	defer srv.Close()

	resp := putChunk(t, srv, token, "?offset=0&total=2", "hi")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a selector-less upload must be accepted, got %d", resp.StatusCode)
	}
	var id AttachmentID
	for i := range id {
		id[i] = 0xab
	}
	if n, known := st.UploadedLen(person, id); !known || n != 2 {
		t.Fatalf("the bytes must live under the session's own account: known=%v n=%d", known, n)
	}
}
