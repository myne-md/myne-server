// SPDX-License-Identifier: AGPL-3.0

package authapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/gcquota"
)

// setupCaps builds an auth handler with the given pre-auth bounds wired.
func setupCaps(t *testing.T, preAuth PreAuthLimiter, maxCreds, maxHs int, ttl time.Duration, now func() time.Time) *httptest.Server {
	t.Helper()
	reg := auth.NewRegistry()
	tokens := auth.NewTokenStore(reg)
	h := New(reg, tokens).WithLimits(maxCreds, maxHs, ttl)
	if preAuth != nil {
		h.WithPreAuthLimiter(preAuth)
	}
	if now != nil {
		h.WithClock(now)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// registerAccount posts a syntactically-valid register for a distinct account.
func registerAccount(t *testing.T, srv *httptest.Server, accountHex string) *http.Response {
	t.Helper()
	resp, _ := postJSON(t, srv.URL+"/auth/register", "", registerReq{
		AccountHashHex: accountHex,
		Username:       accountHex, // AS9: username = account-hash hex
		SaltHex:        strings.Repeat("11", 16),
		Iterations:     1,
		StoredKeyHex:   strings.Repeat("22", 32),
		ServerKeyHex:   strings.Repeat("33", 32),
	})
	return resp
}

func acctHex(i int) string { return fmt.Sprintf("%032x", i) }

// The pre-auth limiter refuses (429) once its global burst is drained, regardless
// of which account the request names.
func TestPreAuth_RateLimited429(t *testing.T) {
	srv := setupCaps(t, gcquota.NewGlobalLimiter(1, 0), 0, 0, 0, nil)
	if resp := registerAccount(t, srv, acctHex(1)); resp.StatusCode != http.StatusOK {
		t.Fatalf("first register status %d, want 200", resp.StatusCode)
	}
	if resp := registerAccount(t, srv, acctHex(2)); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second register status %d, want 429", resp.StatusCode)
	}
}

// The account-map cap refuses new registrations with 503 once full.
func TestRegister_MaxCreds503(t *testing.T) {
	srv := setupCaps(t, nil, 2, 0, 0, nil)
	if resp := registerAccount(t, srv, acctHex(1)); resp.StatusCode != http.StatusOK {
		t.Fatalf("register 1 status %d, want 200", resp.StatusCode)
	}
	if resp := registerAccount(t, srv, acctHex(2)); resp.StatusCode != http.StatusOK {
		t.Fatalf("register 2 status %d, want 200", resp.StatusCode)
	}
	if resp := registerAccount(t, srv, acctHex(3)); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("register 3 status %d, want 503 capacity", resp.StatusCode)
	}
}

// initHS drives one scram/init and returns (status, handshake_id).
func initHS(t *testing.T, srv *httptest.Server, accountHex, username, nonce string) (int, string) {
	t.Helper()
	resp, body := postJSON(t, srv.URL+"/auth/scram/init", "", scramInitReq{
		AccountHashHex: accountHex,
		Username:       username,
		ClientNonce:    nonce,
	})
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, ""
	}
	var ir scramInitResp
	if err := json.Unmarshal(body, &ir); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, ir.HandshakeID
}

// The handshake map is capped and swept: at the cap a new init is 503; once the TTL
// elapses the sweep frees slots so init succeeds again; an expired handshake fails
// final with 401.
func TestScramInit_HandshakeCapAndTTL(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	ttl := 60 * time.Second
	srv := setupCaps(t, nil, 0, 2, ttl, clock)
	acct := acctHex(7)
	user := acct // AS9: username = account-hash hex
	if resp := registerAccount(t, srv, acct); resp.StatusCode != http.StatusOK {
		t.Fatalf("register status %d", resp.StatusCode)
	}

	if s, _ := initHS(t, srv, acct, user, "n1"); s != http.StatusOK {
		t.Fatalf("init 1 status %d, want 200", s)
	}
	if s, _ := initHS(t, srv, acct, user, "n2"); s != http.StatusOK {
		t.Fatalf("init 2 status %d, want 200", s)
	}
	// Map full (2) and nothing expired → 503.
	if s, _ := initHS(t, srv, acct, user, "n3"); s != http.StatusServiceUnavailable {
		t.Fatalf("init 3 status %d, want 503 capacity", s)
	}

	// Elapse past the TTL: n1/n2 expire → the next init sweeps and succeeds.
	advance(ttl + time.Second)
	s, hid := initHS(t, srv, acct, user, "n4")
	if s != http.StatusOK {
		t.Fatalf("init 4 (post-sweep) status %d, want 200", s)
	}

	// Let n4 itself expire, then a final for it must 401 (expired handshake burned).
	advance(ttl + time.Second)
	resp, _ := postJSON(t, srv.URL+"/auth/scram/final", "", scramFinalReq{
		HandshakeID: hid,
		ClientFinal: "c=biws,r=x,p=" + strings.Repeat("A", 43) + "=",
		DeviceIDHex: strings.Repeat("01", 16),
		Path:        "password",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("final on expired handshake status %d, want 401", resp.StatusCode)
	}
}
