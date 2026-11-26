// SPDX-License-Identifier: AGPL-3.0-only

package adminapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/myne-md/myne-server/internal/accounts"
	"github.com/myne-md/myne-server/internal/console"
	"github.com/myne-md/myne-server/internal/ids"
)

func acct(b byte) ids.AccountNumberHash {
	var a ids.AccountNumberHash
	a[0] = b
	return a
}

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s → %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

// shortSock returns a Unix-socket path in a SHORT temp dir. macOS caps sun_path at
// ~104 bytes and t.TempDir() embeds the (long) test name, overflowing it — the real
// deploy path (/run/myne/admin.sock) is short, so this is a test-harness concern only.
func shortSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// dialSocket returns an HTTP client that talks to a Unix domain socket.
func dialSocket(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
}

func TestListen_DisabledWhenEmpty(t *testing.T) {
	ln, err := Listen("")
	if err != nil {
		t.Fatalf("Listen(\"\"): %v", err)
	}
	if ln != nil {
		t.Fatalf("empty path should disable the admin API (nil listener)")
	}
}

func TestListen_BindsLocalOnlyAt0600(t *testing.T) {
	sock := shortSock(t)
	ln, err := Listen(sock)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	if ln.Addr().Network() != "unix" {
		t.Errorf("admin socket network = %q, want unix (never TCP)", ln.Addr().Network())
	}
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket perm = %o, want 0600", perm)
	}
}

func TestListen_RemovesStaleSocket(t *testing.T) {
	sock := shortSock(t)
	if err := os.WriteFile(sock, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(sock) // must remove the stale file, not fail with "address in use"
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	ln.Close()
}

func TestServe_PingOverSocketThenClosesOnCancel(t *testing.T) {
	sock := shortSock(t)
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go Serve(ctx, ln, New(nil, nil, nil, nil, 0).Mux())

	client := dialSocket(sock)
	// Ping serves over the socket.
	resp, err := client.Get("http://unix/admin/ping")
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != `{"status":"ok"}` {
		t.Fatalf("ping = %d %q, want 200 ok", resp.StatusCode, body)
	}

	// Cancel → the server shuts down and stops accepting.
	cancel()
	deadline := time.After(2 * time.Second)
	for {
		if _, err := client.Get("http://unix/admin/ping"); err != nil {
			return // closed
		}
		select {
		case <-deadline:
			t.Fatal("admin server did not close on ctx cancel")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func setupReadRoutes(t *testing.T) *httptest.Server {
	t.Helper()
	a1, a2 := acct(1), acct(2)
	policy := accounts.New(filepath.Join(t.TempDir(), "accounts.json"))
	policy.Update(a1, func(p *accounts.Policy) { p.Frozen = true; p.QuotaOverrideBytes = 500 })
	list := func() []ids.AccountNumberHash { return []ids.AccountNumberHash{a1, a2} }
	used := func(a ids.AccountNumberHash) uint64 {
		if a == a1 {
			return 100
		}
		return 200
	}
	devs := func(a ids.AccountNumberHash) uint64 {
		if a == a1 {
			return 2
		}
		return 1
	}
	srv := httptest.NewServer(New(list, used, devs, policy, 100).Mux())
	t.Cleanup(srv.Close)
	return srv
}

func TestRead_ListMergesLiveStatsAndPolicy(t *testing.T) {
	srv := setupReadRoutes(t)
	var got []accountView
	getJSON(t, srv.URL+"/admin/accounts", &got)
	if len(got) != 2 {
		t.Fatalf("list len = %d, want 2", len(got))
	}
	byHash := map[string]accountView{}
	for _, v := range got {
		byHash[v.AccountHash] = v
	}
	a1 := byHash[hex.EncodeToString(func() []byte { a := acct(1); return a[:] }())]
	if a1.StoredBytes != 100 || a1.DeviceCount != 2 || !a1.Frozen || a1.QuotaOverrideBytes != 500 {
		t.Errorf("acct1 view = %+v, want stored 100 / devices 2 / frozen / override 500", a1)
	}
	a2 := byHash[hex.EncodeToString(func() []byte { a := acct(2); return a[:] }())]
	if a2.StoredBytes != 200 || a2.DeviceCount != 1 || a2.Frozen {
		t.Errorf("acct2 view = %+v, want stored 200 / devices 1 / not frozen", a2)
	}
}

func TestRead_ShowOneAccount(t *testing.T) {
	srv := setupReadRoutes(t)
	a := acct(1)
	var one accountView
	getJSON(t, srv.URL+"/admin/accounts/"+hex.EncodeToString(a[:]), &one)
	if !one.Frozen || one.StoredBytes != 100 {
		t.Errorf("show acct1 = %+v, want frozen + stored 100", one)
	}
	// A malformed hash is a clean 400.
	resp, _ := http.Get(srv.URL + "/admin/accounts/not-hex")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed hash → %d, want 400", resp.StatusCode)
	}
}

func TestRead_StatsAggregate(t *testing.T) {
	srv := setupReadRoutes(t)
	var s statsView
	getJSON(t, srv.URL+"/admin/stats", &s)
	if s.TotalAccounts != 2 || s.TotalStoredBytes != 300 || s.MaxAccounts != 100 {
		t.Errorf("stats = %+v, want 2 accounts / 300 bytes / cap 100", s)
	}
}

func TestRead_NoTimeSeriesOrWallClockFields(t *testing.T) {
	srv := setupReadRoutes(t)
	resp, _ := http.Get(srv.URL + "/admin/accounts")
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, forbidden := range []string{"last_seen", "timestamp", "activity", "updated_at", "wall_clock", "request"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("admin response leaks a %q field — violates the aggregate-only invariant", forbidden)
		}
	}
}

func post(t *testing.T, url, body string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, raw
}

// setupWrite builds a server over an empty policy store with one known account.
func setupWrite(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	a := acct(0x11)
	policy := accounts.New(filepath.Join(t.TempDir(), "accounts.json"))
	list := func() []ids.AccountNumberHash { return []ids.AccountNumberHash{a} }
	z := func(ids.AccountNumberHash) uint64 { return 0 }
	srv := httptest.NewServer(New(list, z, z, policy, 0).Mux())
	t.Cleanup(srv.Close)
	return srv, hex.EncodeToString(a[:])
}

func TestWrite_FreezeUnfreeze(t *testing.T) {
	srv, hx := setupWrite(t)
	base := srv.URL + "/admin/accounts/" + hx

	var v accountView
	resp, raw := post(t, base+"/freeze", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("freeze → %d", resp.StatusCode)
	}
	_ = json.Unmarshal(raw, &v)
	if !v.Frozen {
		t.Errorf("after freeze, frozen = false")
	}
	// Verify it persisted via show.
	getJSON(t, base, &v)
	if !v.Frozen {
		t.Errorf("show after freeze: frozen = false")
	}
	// Unfreeze clears it (entry drops back to default).
	post(t, base+"/unfreeze", "")
	getJSON(t, base, &v)
	if v.Frozen {
		t.Errorf("show after unfreeze: still frozen")
	}
}

func TestWrite_SetAndClearQuota(t *testing.T) {
	srv, hx := setupWrite(t)
	base := srv.URL + "/admin/accounts/" + hx

	var v accountView
	_, raw := post(t, base+"/quota", `{"value":500}`)
	_ = json.Unmarshal(raw, &v)
	if v.QuotaOverrideBytes != 500 {
		t.Errorf("quota override = %d, want 500", v.QuotaOverrideBytes)
	}
	// 0 clears the override (the response omits quota_override_bytes via omitempty,
	// so decode into a FRESH view — a reused one would keep the stale 500).
	var cleared accountView
	_, raw = post(t, base+"/quota", `{"value":0}`)
	_ = json.Unmarshal(raw, &cleared)
	if cleared.QuotaOverrideBytes != 0 {
		t.Errorf("quota override after clear = %d, want 0", cleared.QuotaOverrideBytes)
	}
}

func TestWrite_SetMaxDevices(t *testing.T) {
	srv, hx := setupWrite(t)
	var v accountView
	_, raw := post(t, srv.URL+"/admin/accounts/"+hx+"/max-devices", `{"value":3}`)
	_ = json.Unmarshal(raw, &v)
	if v.MaxDevicesOverride != 3 {
		t.Errorf("max-devices override = %d, want 3", v.MaxDevicesOverride)
	}
}

func TestWrite_MalformedHash400(t *testing.T) {
	srv, _ := setupWrite(t)
	if resp, _ := post(t, srv.URL+"/admin/accounts/not-hex/freeze", ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed hash freeze → %d, want 400", resp.StatusCode)
	}
}

func doDelete(t *testing.T, url string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestDelete_RemovesAndReports(t *testing.T) {
	var got []string
	del := func(a ids.AccountNumberHash) error { got = append(got, hex.EncodeToString(a[:])); return nil }
	srv := httptest.NewServer(New(nil, nil, nil, nil, 0).WithDelete(del).Mux())
	t.Cleanup(srv.Close)
	a := acct(0x11)
	hx := hex.EncodeToString(a[:])
	resp := doDelete(t, srv.URL+"/admin/accounts/"+hx)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete → %d, want 200", resp.StatusCode)
	}
	if len(got) != 1 || got[0] != hx {
		t.Errorf("del closure got %v, want [%s]", got, hx)
	}
}

func TestDelete_NoDeleteWired503(t *testing.T) {
	srv := httptest.NewServer(New(nil, nil, nil, nil, 0).Mux()) // no WithDelete
	t.Cleanup(srv.Close)
	a := acct(0x11)
	resp := doDelete(t, srv.URL+"/admin/accounts/"+hex.EncodeToString(a[:]))
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("delete without a wired closure → %d, want 503", resp.StatusCode)
	}
}

func TestDelete_MalformedHash400(t *testing.T) {
	srv := httptest.NewServer(New(nil, nil, nil, nil, 0).WithDelete(func(ids.AccountNumberHash) error { return nil }).Mux())
	t.Cleanup(srv.Close)
	resp := doDelete(t, srv.URL+"/admin/accounts/not-hex")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed hash delete → %d, want 400", resp.StatusCode)
	}
}

// The panel and this API must render the same row. Both read internal/console, so
// they cannot drift by construction; this pins that, because a future refactor that
// gave the panel its own row builder would drift silently and could put a field past
// the aggregate-only denylist above.
func TestRead_PanelProjectionAndThisAPIAgree(t *testing.T) {
	a1, a2 := acct(1), acct(2)
	policy := accounts.New(filepath.Join(t.TempDir(), "accounts.json"))
	policy.Update(a1, func(p *accounts.Policy) {
		p.Frozen = true
		p.QuotaOverrideBytes = 500
		p.MaxDevicesOverride = 3
	})
	list := func() []ids.AccountNumberHash { return []ids.AccountNumberHash{a1, a2} }
	used := func(a ids.AccountNumberHash) uint64 {
		if a == a1 {
			return 100
		}
		return 200
	}
	devs := func(a ids.AccountNumberHash) uint64 {
		if a == a1 {
			return 2
		}
		return 1
	}

	// What the admin API serves.
	srv := httptest.NewServer(New(list, used, devs, policy, 100).Mux())
	defer srv.Close()
	var viaAPI []accountView
	getJSON(t, srv.URL+"/admin/accounts", &viaAPI)

	// What the panel would render, from the identical projection inputs.
	viaPanel := console.NewProjection(list, used, devs, policy, 100).Accounts()

	if len(viaAPI) != len(viaPanel) {
		t.Fatalf("row count: API %d, panel %d", len(viaAPI), len(viaPanel))
	}
	for i := range viaAPI {
		if viaAPI[i] != viaPanel[i] {
			t.Errorf("row %d diverged:\n  admin API: %+v\n  panel:     %+v", i, viaAPI[i], viaPanel[i])
		}
	}

	// And the same for the aggregate the panel's summary row reads.
	var viaAPIStats statsView
	getJSON(t, srv.URL+"/admin/stats", &viaAPIStats)
	viaPanelStats := console.NewProjection(list, used, devs, policy, 100).Stats()
	if viaAPIStats.TotalAccounts != viaPanelStats.TotalAccounts ||
		viaAPIStats.TotalStoredBytes != viaPanelStats.TotalStoredBytes ||
		viaAPIStats.MaxAccounts != viaPanelStats.MaxAccounts {
		t.Errorf("stats diverged:\n  admin API: %+v\n  panel:     %+v", viaAPIStats, viaPanelStats)
	}
	if viaPanelStats.FrozenAccounts != 1 {
		t.Errorf("panel frozen count = %d, want 1: it must come from the same policy read", viaPanelStats.FrozenAccounts)
	}
}
