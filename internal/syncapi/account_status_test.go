// SPDX-License-Identifier: AGPL-3.0

package syncapi

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

func TestAccountStatus_TokenDerivedNoURLIdentifier(t *testing.T) {
	var calledWith ids.AccountNumberHash
	status := func(a ids.AccountNumberHash) any {
		calledWith = a
		return map[string]string{"account": hex.EncodeToString(a[:])}
	}

	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)
	var a ids.AccountNumberHash
	a[0] = 0x42
	var d ids.DeviceID
	d[0] = 0x01
	res, err := en.Enroll(a, d, auth.PathPassword)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(st, ts).WithAccountStatus(status).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	token := hex.EncodeToString(res.Token)

	// Authed → 200, and the account is the TOKEN's account even though the query
	// carries a DIFFERENT account value (it must be ignored — no URL/query selector).
	resp, _ := do(t, srv, http.MethodGet, "/account/status?account=deadbeefdeadbeefdeadbeefdeadbeef", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authed status → %d, want 200", resp.StatusCode)
	}
	if calledWith != a {
		t.Errorf("account was not token-derived: called with %x, want %x (URL/query honored?)", calledWith, a)
	}

	// Unauthenticated → 401.
	if resp2, _ := do(t, srv, http.MethodGet, "/account/status", "", ""); resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthed status → %d, want 401", resp2.StatusCode)
	}
}
