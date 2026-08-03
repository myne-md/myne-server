// SPDX-License-Identifier: AGPL-3.0

package adminapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
)

// RunCLI is the `myne-server admin <cmd> [args]` thin client (MYND-506). It dials the
// operator admin API over the Unix domain socket at sock and returns a process exit
// code. sock == "" (admin API disabled) is a clear error, as is an unreachable socket
// (server down) — never a panic.
func RunCLI(sock string, args []string) int {
	if sock == "" {
		fmt.Fprintln(os.Stderr, "admin: MYNE_ADMIN_SOCKET is not set (the admin API is disabled)")
		return 2
	}
	// Split flags from positional args.
	jsonOut, yes := false, false
	var pos []string
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		case "--yes":
			yes = true
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) == 0 {
		fmt.Fprintln(os.Stderr, "admin: usage: myne-server admin <list|show|stats|freeze|unfreeze|set-quota|set-max-devices|delete> [account-hash] [value] [--json] [--yes]")
		return 2
	}
	c := newClient(sock)

	// arg1 takes the 32-hex account_number_hash, as printed by `admin list`.
	arg1Hash := func() (string, bool) {
		if len(pos) < 2 {
			fmt.Fprintf(os.Stderr, "admin %s: a 32-hex account_number_hash is required (see: myne-server admin list)\n", pos[0])
			return "", false
		}
		h, err := accountHash(pos[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "admin %s: %v\n", pos[0], err)
			return "", false
		}
		return h, true
	}

	switch pos[0] {
	case "list":
		return c.getPrint("/admin/accounts", jsonOut, printAccounts)
	case "stats":
		return c.getPrint("/admin/stats", jsonOut, printStats)
	case "show":
		h, ok := arg1Hash()
		if !ok {
			return 2
		}
		return c.getPrint("/admin/accounts/"+h, jsonOut, printAccount)
	case "freeze", "unfreeze":
		h, ok := arg1Hash()
		if !ok {
			return 2
		}
		return c.postPrint("/admin/accounts/"+h+"/"+pos[0], nil, jsonOut)
	case "set-quota", "set-max-devices":
		h, ok := arg1Hash()
		if !ok {
			return 2
		}
		if len(pos) < 3 {
			fmt.Fprintf(os.Stderr, "admin %s: a value is required (0 clears the override)\n", pos[0])
			return 2
		}
		v, err := strconv.ParseUint(pos[2], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "admin %s: value must be a non-negative integer\n", pos[0])
			return 2
		}
		route := strings.TrimPrefix(pos[0], "set-") // set-quota→quota, set-max-devices→max-devices
		body, _ := json.Marshal(setReq{Value: v})
		return c.postPrint("/admin/accounts/"+h+"/"+route, body, jsonOut)
	case "delete":
		h, ok := arg1Hash()
		if !ok {
			return 2
		}
		if !yes {
			fmt.Fprintln(os.Stderr, "admin delete: refusing without --yes (this permanently deletes the account's vault + attachments + auth)")
			return 2
		}
		raw, code, err := c.do(http.MethodDelete, "/admin/accounts/"+h, nil)
		return finish(raw, code, err, jsonOut, func(b []byte) { fmt.Printf("deleted %s\n", h) })
	default:
		fmt.Fprintf(os.Stderr, "admin: unknown subcommand %q\n", pos[0])
		return 2
	}
}

type client struct {
	hc *http.Client
}

func newClient(sock string) *client {
	return &client{hc: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}}
}

func (c *client) do(method, path string, body []byte) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, "http://unix"+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, nil
}

func (c *client) getPrint(path string, jsonOut bool, table func([]byte)) int {
	raw, code, err := c.do(http.MethodGet, path, nil)
	return finish(raw, code, err, jsonOut, table)
}

func (c *client) postPrint(path string, body []byte, jsonOut bool) int {
	raw, code, err := c.do(http.MethodPost, path, body)
	return finish(raw, code, err, jsonOut, printAccount)
}

// finish maps a response to output + an exit code. A transport error (socket absent)
// is a clear stderr line + exit 1; a non-2xx status prints the body + exit 1.
func finish(raw []byte, code int, err error, jsonOut bool, table func([]byte)) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin: cannot reach the admin socket (is the server running?): %v\n", err)
		return 1
	}
	if code < 200 || code >= 300 {
		fmt.Fprintf(os.Stderr, "admin: server returned %d: %s\n", code, strings.TrimSpace(string(raw)))
		return 1
	}
	if jsonOut {
		fmt.Println(strings.TrimSpace(string(raw)))
		return 0
	}
	table(raw)
	return 0
}

func printAccounts(raw []byte) {
	var vs []accountView
	if json.Unmarshal(raw, &vs) != nil {
		fmt.Println(strings.TrimSpace(string(raw)))
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ACCOUNT\tBYTES\tDEVICES\tFROZEN\tQUOTA_OVR\tMAXDEV_OVR")
	for _, v := range vs {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%t\t%d\t%d\n", v.AccountHash, v.StoredBytes, v.DeviceCount, v.Frozen, v.QuotaOverrideBytes, v.MaxDevicesOverride)
	}
	tw.Flush()
}

func printAccount(raw []byte) {
	var v accountView
	if json.Unmarshal(raw, &v) != nil {
		fmt.Println(strings.TrimSpace(string(raw)))
		return
	}
	fmt.Printf("account:      %s\nstored_bytes: %d\ndevices:      %d\nfrozen:       %t\nquota_ovr:    %d\nmaxdev_ovr:   %d\n",
		v.AccountHash, v.StoredBytes, v.DeviceCount, v.Frozen, v.QuotaOverrideBytes, v.MaxDevicesOverride)
}

func printStats(raw []byte) {
	var s statsView
	if json.Unmarshal(raw, &s) != nil {
		fmt.Println(strings.TrimSpace(string(raw)))
		return
	}
	fmt.Printf("total_accounts:     %d\ntotal_stored_bytes: %d\nmax_accounts:       %d\n", s.TotalAccounts, s.TotalStoredBytes, s.MaxAccounts)
}

// accountHash resolves an operator-supplied identifier to an account_number_hash hex.
//
// It accepts the 32-hex `account_number_hash` and NOTHING ELSE. `admin list`
// prints that hash for every account, which is where an operator gets it.
//
// It deliberately does not accept a raw account number. It used to, by
// stripping the "MY-" prefix and the group dashes, uppercasing, and hashing
// the remaining 20 characters — which is not what `account-number.md` §5-6
// defines. `normalize` also verifies that every character is in the Crockford
// alphabet and that the Damm-32 check character is correct; skipping those two
// steps meant a mistyped or transposed number — exactly the error class the
// check character exists to catch, and which every client entry point refuses —
// was silently accepted and hashed into a phantom account. `admin delete` is
// one of the commands that took this path.
//
// The repair is to delete this second implementation rather than complete it.
// A faithful port needs NFKD, i.e. `golang.org/x/text/unicode/norm`, which
// would be this server's first third-party dependency (`go.mod` declares zero),
// and adding a dependency is a security decision. A second copy of the frozen
// §4.2 Damm-32 quasigroup table would also be a new drift surface for a
// load-bearing constant, to buy operator ergonomics on a local admin socket.
func accountHash(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) == 32 {
		if _, err := hex.DecodeString(strings.ToLower(s)); err == nil {
			return strings.ToLower(s), nil
		}
	}
	return "", fmt.Errorf("not a 32-hex account_number_hash (admin list prints it; raw account numbers are not accepted)")
}
