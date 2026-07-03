// SPDX-License-Identifier: AGPL-3.0

package authapi

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

// A pre-auth /auth/register body larger than MaxAuthBodySize is refused (400):
// http.MaxBytesReader cuts the stream so json.Decode fails, bounding the memory
// an unauthenticated caller can force the server to buffer.
func TestRegister_OversizeBody_Rejected(t *testing.T) {
	c := newEnv(t)
	big := strings.Repeat("a", MaxAuthBodySize+1024)
	resp, _ := postJSON(t, c.srv.URL+"/auth/register", "", registerReq{
		AccountHashHex: c.account,
		Username:       big, // inflates the JSON body past the cap
		SaltHex:        hex.EncodeToString(c.salt),
		Iterations:     c.iters,
		StoredKeyHex:   strings.Repeat("00", 32),
		ServerKeyHex:   strings.Repeat("00", 32),
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversize register status %d, want 400", resp.StatusCode)
	}
}

// A normal-size register still succeeds under the cap (regression guard).
func TestRegister_NormalBody_OK(t *testing.T) {
	c := newEnv(t)
	c.register(t) // fails the test internally if status != 200
}
