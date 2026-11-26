// SPDX-License-Identifier: AGPL-3.0-only

package adminapi

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/accounts"
	"github.com/myne-md/myne-server/internal/ids"
)

// serveCLI starts a real admin server over a short socket with stub deps and returns
// the socket path + the policy store (to verify writes) + a recorder of deletes.
func serveCLI(t *testing.T) (string, *accounts.Store, *[]string) {
	t.Helper()
	sock := shortSock(t)
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	a := acct(0x11)
	policy := accounts.New(filepath.Join(t.TempDir(), "accounts.json"))
	deleted := &[]string{}
	list := func() []ids.AccountNumberHash { return []ids.AccountNumberHash{a} }
	used := func(ids.AccountNumberHash) uint64 { return 42 }
	devs := func(ids.AccountNumberHash) uint64 { return 1 }
	del := func(x ids.AccountNumberHash) error { *deleted = append(*deleted, hex.EncodeToString(x[:])); return nil }
	h := New(list, used, devs, policy, 10).WithDelete(del)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Serve(ctx, ln, h.Mux())
	return sock, policy, deleted
}

func TestRunCLI_HappyPath(t *testing.T) {
	sock, policy, deleted := serveCLI(t)
	a := acct(0x11)
	hx := hex.EncodeToString(a[:])

	for _, args := range [][]string{{"list"}, {"stats"}, {"show", hx}, {"list", "--json"}} {
		if code := RunCLI(sock, args); code != 0 {
			t.Errorf("RunCLI %v = %d, want 0", args, code)
		}
	}
	// freeze takes effect on the server's policy store.
	if RunCLI(sock, []string{"freeze", hx}) != 0 || !policy.Frozen(a) {
		t.Errorf("freeze did not take")
	}
	if RunCLI(sock, []string{"unfreeze", hx}) != 0 || policy.Frozen(a) {
		t.Errorf("unfreeze did not take")
	}
	if RunCLI(sock, []string{"set-quota", hx, "500"}) != 0 || policy.Get(a).QuotaOverrideBytes != 500 {
		t.Errorf("set-quota did not take")
	}
	if RunCLI(sock, []string{"set-max-devices", hx, "3"}) != 0 || policy.Get(a).MaxDevicesOverride != 3 {
		t.Errorf("set-max-devices did not take")
	}
	// delete requires --yes.
	if RunCLI(sock, []string{"delete", hx}) != 2 {
		t.Errorf("delete without --yes should be exit 2")
	}
	if len(*deleted) != 0 {
		t.Errorf("delete without --yes must not call the delete path")
	}
	if RunCLI(sock, []string{"delete", hx, "--yes"}) != 0 || len(*deleted) != 1 || (*deleted)[0] != hx {
		t.Errorf("delete --yes did not delete: %v", *deleted)
	}
}

func TestRunCLI_EmptySocketDisabled(t *testing.T) {
	if RunCLI("", []string{"list"}) != 2 {
		t.Errorf("empty socket (admin disabled) should be exit 2")
	}
}

func TestRunCLI_SocketAbsentClearError(t *testing.T) {
	// A well-formed but non-existent socket → transport error → exit 1 (not a panic).
	if RunCLI(filepath.Join(t.TempDir(), "nope.sock"), []string{"list"}) != 1 {
		t.Errorf("absent socket should be exit 1")
	}
}

func TestRunCLI_UnknownSubcommand(t *testing.T) {
	sock, _, _ := serveCLI(t)
	if RunCLI(sock, []string{"bogus"}) != 2 {
		t.Errorf("unknown subcommand should be exit 2")
	}
}

func TestAccountHash_AcceptsOnlyTheHash(t *testing.T) {
	// A 32-hex string is the account_number_hash verbatim (case-normalized).
	hx := strings.Repeat("ab", 16)
	if got, err := accountHash(strings.ToUpper(hx)); err != nil || got != hx {
		t.Errorf("32-hex passthrough = %q, %v; want %q", got, err, hx)
	}

	// A raw account number is REFUSED, in every form an operator might type.
	// The CLI holds no Crockford-alphabet check and no Damm-32 verifier, so it
	// cannot tell a real number from a mistyped one; accepting either would
	// hash a phantom account. `admin list` prints the hash — that is the input.
	for _, raw := range []string{
		"MY-ABCD-EFGH-JKMN-PQRS-TVWX", // display form
		"0123456789ABCDEFGHJT",        // canonical form, Damm-valid
		"0132456789ABCDEFGHJT",        // the same number with two chars transposed
		"O123456789ABCDEFGHJT",        // 'O' is not in the Crockford alphabet
	} {
		if got, err := accountHash(raw); err == nil {
			t.Errorf("accountHash(%q) = %q, want refusal", raw, got)
		}
	}

	// Garbage is a clean error, not a panic.
	if _, err := accountHash("nope"); err == nil {
		t.Errorf("garbage identifier should error")
	}
}
