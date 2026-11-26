// SPDX-License-Identifier: AGPL-3.0-only

package syncapi

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/gcquota"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// `/b2b/vaults/{hash}/retire` is registered on the SYNC mux, not on authapi's route list, so
// it looked covered by `WithPolicy` and was not: the limiter is consulted per HANDLER, and
// this one never called it (myne-md/myne-server#18). The regression pin is a real one here,
// because a fix scoped to "wrap the /b2b routes in authapi" would miss this route entirely.
func TestRetire_IsRateLimited(t *testing.T) {
	srv, owner, member, _, vault, _ := setupB2B(t, 7*24*time.Hour, true)
	defer srv.Close()
	path := "/b2b/vaults/" + hex.EncodeToString(vault[:]) + "/retire"
	body := retireBody(t, vault, pushBlobIDHex(9))

	// No limiter installed: the route works, which is what makes the next case a statement
	// about the limiter rather than about the route being broken.
	if resp, b := do(t, srv, http.MethodPost, path, owner, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("owner retire without a policy = %d: %s", resp.StatusCode, b)
	}

	// A bucket with no refill and one token: the first call spends it, the second is refused.
	srv2, owner2, _, vault2, _ := setupB2BPolicy(t, gcquota.NewRateLimiter(1, 0))
	defer srv2.Close()
	path2 := "/b2b/vaults/" + hex.EncodeToString(vault2[:]) + "/retire"
	body2 := retireBody(t, vault2, pushBlobIDHex(9))
	if resp, b := do(t, srv2, http.MethodPost, path2, owner2, body2); resp.StatusCode != http.StatusOK {
		t.Fatalf("first retire with one token = %d: %s", resp.StatusCode, b)
	}
	resp, b := do(t, srv2, http.MethodPost, path2, owner2, body2)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second retire = %d, want 429: %s", resp.StatusCode, b)
	}
	if code := errorCode(t, b); code != "rate" {
		t.Fatalf("refusal error code = %q, want the sync surface's `rate`", code)
	}

	// The member token is refused by AUTHORITY before the limiter is reached, so the 403 a
	// member sees is not a rate-limit side effect.
	if resp, _ := do(t, srv2, http.MethodPost, path2, member, body2); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member retire = %d, want 403", resp.StatusCode)
	}
}

// setupB2BPolicy is setupB2B with a rate limiter installed, so the retire route can be driven
// to its refusal. It mirrors setupB2B's construction (the same fake membership and registry)
// rather than reaching into it, because the point is the POLICY wiring and a helper that
// installed one for every other test would hide which case is the limiter's.
func setupB2BPolicy(t *testing.T, rl RateLimiter) (*httptest.Server, string, string, ids.AccountNumberHash, *store.Retirements) {
	t.Helper()
	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)
	var vault ids.AccountNumberHash
	vault[0] = 0x42
	var d ids.DeviceID
	d[0] = 0x01
	if _, err := en.Enroll(vault, d, auth.PathPassword); err != nil {
		t.Fatal(err)
	}
	fm := &fakeMembership{
		ownerBearer:  strings.Repeat("aa", 32),
		memberBearer: strings.Repeat("bb", 32),
		vault:        vault,
		owners:       map[ids.AccountNumberHash]bool{vault: true},
	}
	rets := store.NewRetirements(7 * 24 * time.Hour)
	mux := http.NewServeMux()
	New(st, ts).WithPolicy(rl, nil).WithMembership(fm).WithRetirements(rets).Register(mux)
	return httptest.NewServer(mux), fm.ownerBearer, fm.memberBearer, vault, rets
}
