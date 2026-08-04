// SPDX-License-Identifier: AGPL-3.0

package syncapi

import (
	"errors"
	"net/http"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// failingMetaStore refuses every vault.meta write and stores nothing — the shape
// of a full volume, an unwritable account dir, or an account tombstoned by
// DeleteAccount between the auth check and the write.
type failingMetaStore struct {
	store.BlobStore
}

func (failingMetaStore) SetMeta(ids.AccountNumberHash, []byte) error {
	return errors.New("simulated store write failure")
}

// PUT /vault.meta must not answer {"ok":true} for a meta the store refused. The
// device reads that 200 as "published": it clears the dirty marker (persisted, so
// a restart does not recover it) and pins the uploaded meta as its baseline. The
// upload is therefore never retried, and the next cycle sees the stale server
// copy as an authoritative remote change and adopts it — rolling back, on the
// very device that made it, the password change this meta carried.
func TestMetaPut_StoreWriteFailureIsReported(t *testing.T) {
	srv, token := setupWith(t, failingMetaStore{store.NewMemStore()})
	defer srv.Close()

	resp, body := do(t, srv, http.MethodPut, "/vault.meta", token, "new-password-side-wrap")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("PUT /vault.meta = %d %s, want 500 — the store rejected the write", resp.StatusCode, body)
	}
	// And the meta the client was told about must not be readable, because it
	// was never stored: the 404 is what proves the 200 would have been a lie.
	if resp, _ := do(t, srv, http.MethodGet, "/vault.meta", token, ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /vault.meta = %d, want 404 — nothing was stored", resp.StatusCode)
	}
}
