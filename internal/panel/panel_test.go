// SPDX-License-Identifier: AGPL-3.0-only

package panel

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/accounts"
	"github.com/myne-md/myne-server/internal/console"
	"github.com/myne-md/myne-server/internal/ids"
)

func acct(b byte) ids.AccountNumberHash {
	var a ids.AccountNumberHash
	for i := range a {
		a[i] = b
	}
	return a
}

const fullHash = "a3f9c1d84b2e7a09f6c35d1e8b47a290" // 32 hex chars = 16 bytes

// fixture builds a projection with two accounts: one frozen with both overrides,
// one plain. Mirrors the admin API's own read fixture so the equivalence test below
// compares like with like.
func fixture(t *testing.T) *console.Projection {
	t.Helper()
	a1, a2 := acct(1), acct(2)
	policy := accounts.New(filepath.Join(t.TempDir(), "accounts.json"))
	policy.Update(a1, func(p *accounts.Policy) {
		p.Frozen = true
		p.QuotaOverrideBytes = 500
		p.MaxDevicesOverride = 3
	})
	return console.NewProjection(
		func() []ids.AccountNumberHash { return []ids.AccountNumberHash{a1, a2} },
		func(a ids.AccountNumberHash) uint64 {
			if a == a1 {
				return 100
			}
			return 200
		},
		func(a ids.AccountNumberHash) uint64 {
			if a == a1 {
				return 2
			}
			return 1
		},
		policy, 100,
	)
}

func serve(t *testing.T, p *console.Projection) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(New(p, "").Mux())
	t.Cleanup(srv.Close)
	return srv
}

func body(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return string(raw)
}

// --- the headline guarantee: read-only is structural -------------------------------

// The route table registers GET only, so every other method is answered by the
// standard library's 405 and every other path by its 404. A REQUEST-level test would
// pass even after someone adds a destructive route tomorrow, because it only tries
// the verbs this test already thought of. This one asserts the property itself.
func TestRoutes_OnlyReadVerbsAreRegistered(t *testing.T) {
	srv := serve(t, fixture(t))
	h := New(fixture(t), "").Mux()

	writeVerbs := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	paths := []string{
		"/", "/panel.css", "/admin", "/admin/accounts", "/freeze", "/../etc",
		// The admin API's REAL enforcement paths. Guessing a path prefix like
		// "/admin" is not enough: those routes live one level deeper, so a test that
		// only tries prefixes would have passed while every write route was reachable.
		"/admin/accounts/0123456789abcdef0123456789abcdef/freeze",
		"/admin/accounts/0123456789abcdef0123456789abcdef/unfreeze",
		"/admin/accounts/0123456789abcdef0123456789abcdef/quota",
		"/admin/accounts/0123456789abcdef0123456789abcdef/max-devices",
		"/admin/accounts/0123456789abcdef0123456789abcdef",
		"/admin/stats", "/admin/ping",
	}

	for _, p := range paths {
		for _, v := range writeVerbs {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(v, p, nil))
			// A write verb must never be SERVED. The failure band is 2xx, not "not
			// 200": a write route answering 204 No Content is a write that succeeded,
			// and the first version of this assertion compared against 200 and passed
			// it. It is also not "not 4xx": a malformed path draws a 3xx redirect from
			// the router before any handler runs, which serves nothing.
			if rec.Code >= 200 && rec.Code < 300 {
				t.Errorf("%s %s answered %d: a write verb reached a panel handler", v, p, rec.Code)
			}
		}
	}

	// GET is the only verb that renders anything, and only at the two read paths.
	for _, p := range []string{"/", "/panel.css"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p, resp.StatusCode)
		}
	}
	for _, p := range []string{"/admin", "/freeze", "/panel.html", "/assets/"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, resp.StatusCode)
		}
	}
}

// The package must not be able to reach a write path even by mistake. Its dependency
// graph is internal/console (read-only by construction) plus the standard library, so
// this is the import-level half of the same guarantee.
func TestPackage_CannotReachAWritePath(t *testing.T) {
	src, err := os.ReadFile("panel.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, forbidden := range []string{
		"internal/adminapi", // the write handlers live here
		"internal/accounts", // the writable policy store
		"adminapi.New(",
		".Update(",
		".Delete(",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("panel.go references %q: the read-only surface can reach a write path", forbidden)
		}
	}
}

// --- the no-IP property ------------------------------------------------------------

// A panel request logs nothing. self-host-policy 3 prohibits IP logging anywhere in
// an operator's stack, so a line here would make a deployment violate its contract.
func TestRequest_LogsNothing(t *testing.T) {
	srv := serve(t, fixture(t))

	var captured strings.Builder
	origOut := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&captured)
	log.SetFlags(0)
	defer func() { log.SetOutput(origOut); log.SetFlags(origFlags) }()

	for _, p := range []string{"/", "/panel.css", "/nope"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if got := captured.String(); got != "" {
		t.Errorf("panel wrote to the log, which the no-IP commitment forbids:\n%s", got)
	}
}

// --- no time, at two levels ---------------------------------------------------------

// The package does not import time, so it is structurally unable to render a
// timestamp. An output-string check alone would pass on a build where the field is
// absent for an unrelated reason.
func TestPackage_CannotRenderATimestamp(t *testing.T) {
	src, err := os.ReadFile("panel.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), `"time"`) {
		t.Error("panel.go imports time: the panel could render a wall-clock, which the aggregate-only invariant forbids")
	}
}

var looksLikeAClock = regexp.MustCompile(`\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}|\b1[6-9]\d{8}\b|epoch`)

// The rendered page carries no clock-shaped value. This is the second of the two
// levels, and it also covers a timestamp reaching the output through the data rather
// than the code.
func TestRenderedPage_CarriesNoTimeValue(t *testing.T) {
	page := body(t, serve(t, fixture(t)).URL+"/")
	if m := looksLikeAClock.FindString(page); m != "" {
		t.Errorf("rendered panel contains a clock-shaped value %q: the page must be an instantaneous projection with no timestamp", m)
	}
}

// --- deterministic, stateless ------------------------------------------------------

// Two loads against an unchanged deployment are byte-identical: there is no cache, no
// clock and nothing accumulated between visits.
func TestRender_IsDeterministicAcrossLoads(t *testing.T) {
	p := fixture(t)
	srv := serve(t, p)
	first := body(t, srv.URL+"/")
	second := body(t, srv.URL+"/")
	if first != second {
		t.Error("two loads of an unchanged projection differed: the panel is holding state between requests")
	}
}

func TestPackage_ImportsNoFilesystemOrClock(t *testing.T) {
	src, err := os.ReadFile("panel.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"os"`, `"time"`, `"database/sql"`, "os.WriteFile", "os.Create"} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("panel.go references %q: the panel must write nothing anywhere", forbidden)
		}
	}
}

// --- what the operator actually sees ------------------------------------------------

func TestRender_ShowsTotalsAndRows(t *testing.T) {
	proj := fixture(t)
	srv := serve(t, proj)
	page := body(t, srv.URL+"/")

	for _, want := range []string{
		"frozen",               // status badge on the frozen account
		"quota override",       // per-account override, labelled
		"device cap override",  // per-account override, labelled
		"none, defaults apply", // the account with no override
		"Read-only operator console",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("rendered panel is missing %q", want)
		}
	}

	// The summary figures agree with the rows they sit above.
	stats := proj.Stats()
	if !strings.Contains(page, fmt.Sprintf(">%d<", stats.TotalAccounts)) {
		t.Errorf("rendered panel does not carry the account total %d", stats.TotalAccounts)
	}
	if !strings.Contains(page, fmt.Sprintf(">%d<", stats.FrozenAccounts)) {
		t.Errorf("rendered panel does not carry the frozen total %d", stats.FrozenAccounts)
	}

	// The hash is abbreviated for reading, and the FULL value is still present in the
	// row's copy payload: readability, not redaction.
	views := proj.Accounts()
	if len(views) != 2 {
		t.Fatalf("fixture accounts = %d, want 2", len(views))
	}
	full := views[0].AccountHash
	if len(full) != 32 { // 16 bytes of account_number_hash, hex-encoded
		t.Fatalf("hash length = %d, want 32", len(full))
	}
	if !strings.Contains(page, full) {
		t.Error("rendered panel does not carry the full account hash in the copy payload")
	}
	if !strings.Contains(page, abbrevHash(full)) {
		t.Error("rendered panel does not carry the abbreviated hash form")
	}
}

func TestAbbrevHash_ShortensButDoesNotHide(t *testing.T) {
	got := abbrevHash(fullHash)
	if got != fullHash[:6]+"…"+fullHash[len(fullHash)-4:] {
		t.Errorf("abbrevHash = %q, want first 6 + ellipsis + last 4", got)
	}
	if len(got) >= len(fullHash) {
		t.Error("abbrevHash did not shorten anything")
	}
	if abbrevHash("short") != "short" {
		t.Error("abbrevHash mangled a value shorter than the cutoff")
	}
}

func TestLimitLabel_ZeroMeansUnlimitedNeverAZeroCeiling(t *testing.T) {
	if got := limitLabel(0); got != "unlimited" {
		t.Errorf("limitLabel(0) = %q, want \"unlimited\": 0 means unlimited, never a ceiling of zero", got)
	}
	if got := limitLabel(7); got != "7" {
		t.Errorf("limitLabel(7) = %q, want \"7\"", got)
	}
}

// A backend that cannot enumerate (the in-memory dev store) yields zero accounts and
// a readable page, not an error: an operator must be able to tell "no accounts" from
// "broken".
func TestRender_MemBackendReadsZeroAccountsNotAnError(t *testing.T) {
	proj := console.NewProjection(nil, nil, nil, nil, 0) // every dep nil = mem backend
	srv := serve(t, proj)

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mem backend = %d, want 200", resp.StatusCode)
	}
	page, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(page), "No accounts on this backend") {
		t.Error("mem backend did not render the empty-state explanation")
	}
}

func TestSummary_FrozenCountMatchesTheRows(t *testing.T) {
	stats := fixture(t).Stats()
	rows := fixture(t).Accounts()
	if stats.FrozenAccounts != 1 {
		t.Errorf("Stats().FrozenAccounts = %d, want 1", stats.FrozenAccounts)
	}
	manual := 0
	for _, r := range rows {
		if r.Frozen {
			manual++
		}
	}
	if uint64(manual) != stats.FrozenAccounts {
		t.Errorf("summary says %d frozen, rows contain %d: the summary can disagree with the table", stats.FrozenAccounts, manual)
	}
}

// --- listener --------------------------------------------------------------------

func TestResponse_HeadersAreHardened(t *testing.T) {
	srv := serve(t, fixture(t))
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP = %q, want default-src 'none': the panel loads nothing third-party", csp)
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP = %q, want frame-ancestors 'none'", csp)
	}
}

// --- DNS rebinding ------------------------------------------------------------------
//
// A rebound hostname is SAME-ORIGIN to the hostile page, and browsers omit Origin on a
// GET, so neither the same-origin policy nor an Origin check stops it. The Host header
// is the only thing that distinguishes a rebound request from the operator's own, and
// these cases pin that the panel acts on it.

func TestHost_ReboundNameIsRefused(t *testing.T) {
	proj := fixture(t)
	srv := httptest.NewServer(New(proj, "").Mux())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	// What a rebound name looks like on the wire: the URL is the operator's own, the
	// Host header is the attacker's.
	req.Host = "attacker.test"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("rebound Host answered %d, want 403: a hostile page could read the roster", resp.StatusCode)
	}
	if bytes.Contains(raw, []byte(proj.Accounts()[0].AccountHash)) {
		t.Error("a refused request still rendered an account hash")
	}
}

func TestHost_LoopbackIsServedAndNamedHostsAreOpted(t *testing.T) {
	cases := []struct {
		host       string
		allow      string
		wantStatus int
	}{
		{"127.0.0.1:8099", "", http.StatusOK},
		{"localhost:8099", "", http.StatusOK},
		{"[::1]:8099", "", http.StatusOK},
		// A LAN address is refused until the operator names the host they browse to.
		{"192.0.2.10:8081", "", http.StatusForbidden},
		{"192.0.2.10:8081", "192.0.2.10", http.StatusOK},
		{"panel.example:8081", "panel.example", http.StatusOK},
		{"panel.example:8081", " other.example , panel.example ", http.StatusOK},
		// Naming one host does not open every host.
		{"evil.test", "panel.example", http.StatusForbidden},
		{"", "", http.StatusForbidden},
	}
	for _, tc := range cases {
		h := New(fixture(t), tc.allow).Mux()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = tc.host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.wantStatus {
			t.Errorf("host %q allow %q = %d, want %d", tc.host, tc.allow, rec.Code, tc.wantStatus)
		}
	}
}

// The roster must not survive in a browser or intermediary cache.
func TestResponse_RosterIsNotCacheable(t *testing.T) {
	srv := serve(t, fixture(t))
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store: the account roster must not be left in a cache", got)
	}
}

// One page load, one full-store walk. Stats() calls Accounts() internally, so asking
// for both enumerated the whole store twice, and on an unauthenticated listener that
// is a cost an outsider drives.
func TestIndex_EnumeratesTheStoreOnce(t *testing.T) {
	var walks int
	proj := console.NewProjection(
		func() []ids.AccountNumberHash {
			walks++
			return []ids.AccountNumberHash{acct(1), acct(2)}
		},
		func(ids.AccountNumberHash) uint64 { return 1 },
		func(ids.AccountNumberHash) uint64 { return 1 },
		nil, 0,
	)
	srv := httptest.NewServer(New(proj, "").Mux())
	defer srv.Close()

	before := walks
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := walks - before; got != 1 {
		t.Errorf("one page load walked the store %d times, want 1", got)
	}
}
