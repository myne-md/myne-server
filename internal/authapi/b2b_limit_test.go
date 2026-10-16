// SPDX-License-Identifier: AGPL-3.0

package authapi

import (
	"net/http"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

// The B2B routes' rate limit (myne-md/myne-server#18). Before it, these ten routes were the
// one part of the API bounded by nothing: the sync routes carried a per-account bucket and
// the pre-auth surface carried global ones, so an authenticated member could drive unlimited
// profile writes, invites and membership changes at a server that advertised per-account
// bounds.

type recordingLimiter struct {
	allow bool
	keys  []ids.AccountNumberHash
}

func (r *recordingLimiter) Allow(a ids.AccountNumberHash) bool {
	r.keys = append(r.keys, a)
	return r.allow
}

func TestB2BRoutes_RefuseWhenTheLimiterSaysNo(t *testing.T) {
	env := newB2BEnv(t)
	lim := &recordingLimiter{allow: false}
	env.h.WithB2BRateLimiter(lim)

	// A representative route from each family the issue names: the invite relay, membership
	// management, a profile write.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/b2b/invites"},
		{http.MethodPost, "/b2b/vaults/" + b2bVaultA + "/members"},
		{http.MethodPut, "/b2b/vaults/" + b2bVaultA + "/profiles/" + b2bAnybody},
	} {
		resp, body := sendJSON(t, tc.method, env.srv.URL+tc.path, "any-bearer", nil)
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("%s %s = %d, want 429 (body %s)", tc.method, tc.path, resp.StatusCode, body)
		}
		if !tbContains(string(body), `"error_code":"rate"`) {
			t.Fatalf("%s %s refusal body = %s, want the sync surface's `rate` shape", tc.method, tc.path, body)
		}
	}
	if len(lim.keys) == 0 {
		t.Fatal("the limiter was never consulted, so this test proves nothing about the wiring")
	}
	// An unauthenticated attempt is still work: it lands in one shared bucket rather than
	// escaping the bound, which is the whole point of keying on the resolved account.
	for _, k := range lim.keys {
		if k != (ids.AccountNumberHash{}) {
			t.Fatalf("an unresolvable bearer was charged to %x, want the shared zero key", k)
		}
	}
}

func TestB2BRoutes_AreChargedToTheVaultOfAMembershipToken(t *testing.T) {
	env := newB2BEnv(t)
	lim := &recordingLimiter{allow: true}
	env.h.WithB2BRateLimiter(lim)

	// A real membership token: the owner binds itself, and the binding response carries the
	// per-vault token the binding minted.
	_, vaultBearer := env.account(t, b2bVaultA, 0x51)
	resp, bind := env.bind(t, b2bVaultA, vaultBearer, b2bOwner, "owner")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("binding the owner = %d", resp.StatusCode)
	}
	if bind.TokenHex == "" {
		t.Fatal("the owner binding returned no membership token")
	}

	lim.keys = nil
	if r, body := sendJSON(t, http.MethodGet, env.srv.URL+"/b2b/vaults/"+b2bVaultA+"/invites", bind.TokenHex, nil); r.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("the limiter refused with allow=true: %s", body)
	}
	if len(lim.keys) != 1 {
		t.Fatalf("limiter consulted %d times, want 1", len(lim.keys))
	}
	if want := acct(t, b2bVaultA); lim.keys[0] != want {
		t.Fatalf("charged to %x, want the vault %x (a membership token authorises against the vault)",
			lim.keys[0], want)
	}
}

// The refusal must not depend on presenting valid credentials: a request with no bearer is
// charged to the shared bucket, so the route cannot be flooded through the unauthenticated
// door either.
func TestB2BRoutes_UnmeteredWhenNoLimiterIsInstalled(t *testing.T) {
	env := newB2BEnv(t)
	resp, _ := sendJSON(t, http.MethodGet, env.srv.URL+"/b2b/invites", "", nil)
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Fatal("no limiter is installed, so nothing may answer 429 (the mem-backend path)")
	}
}

func tbContains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
