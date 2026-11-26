// SPDX-License-Identifier: AGPL-3.0-only

package authpersist

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/authapi"
	"github.com/myne-md/myne-server/internal/gcquota"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// env is one wired persistence environment: the three stores + a coordinator + an
// httptest server over the auth routes, all sharing one auth.json under dir.
type env struct {
	dir    string
	path   string
	reg    *auth.Registry
	tokens *auth.TokenStore
	h      *authapi.Handler
	coord  *Coordinator
	srv    *httptest.Server
}

func newEnv(t *testing.T, dir string) *env {
	t.Helper()
	reg := auth.NewRegistry()
	tokens := auth.NewTokenStore(reg)
	h := authapi.New(reg, tokens)
	path := filepath.Join(dir, "auth.json")
	coord, err := Wire(reg, tokens, h, path)
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &env{dir: dir, path: path, reg: reg, tokens: tokens, h: h, coord: coord, srv: srv}
}

func acct(b byte) ids.AccountNumberHash { var a ids.AccountNumberHash; a[0] = b; return a }
func dev(b byte) ids.DeviceID           { var d ids.DeviceID; d[0] = b; return d }

// postRegister drives POST /auth/register (uploads a SCRAM verifier; no proof needed).
// This handler holds h.mu AND triggers the persistence save — the deadlock probe.
func (e *env) postRegister(t *testing.T, a ids.AccountNumberHash) int {
	t.Helper()
	body := registerBody(a)
	resp, err := http.Post(e.srv.URL+"/auth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("register POST: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func registerBody(a ids.AccountNumberHash) string {
	// AS9: the register endpoint only accepts username == account-hash hex.
	return `{"account_hash_hex":"` + hex.EncodeToString(a[:]) +
		`","username":"` + hex.EncodeToString(a[:]) +
		`","salt_hex":"` + strings.Repeat("ab", 16) +
		`","iterations":1,"stored_key_hex":"` + strings.Repeat("cd", 32) +
		`","server_key_hex":"` + strings.Repeat("ef", 32) + `"}`
}

// enroll registers a device + issues a token directly (recovery self-approves), then
// persists. Returns the issued token hex.
func (e *env) enroll(t *testing.T, a ids.AccountNumberHash, d ids.DeviceID) string {
	t.Helper()
	res, err := auth.NewEnrollment(e.reg, e.tokens).Enroll(a, d, auth.PathRecovery)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	e.coord.Save()
	return hex.EncodeToString(res.Token)
}

// ---- the central deadlock probe + creds round-trip ----

func TestPersist_RegisterDeadlockFreeAndCredSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, dir)
	a := acct(0x42)

	// The register handler holds h.mu and fires the persistence hook (now a lock-free
	// dirty-marker, not a synchronous Save). A returned status proves it does not hang.
	if code := e.postRegister(t, a); code != 200 {
		t.Fatalf("register: status %d (a hang/deadlock would never reach here)", code)
	}
	// Persistence is coalesced now — flush to materialise the write, then assert it landed.
	e.coord.Flush()
	if _, err := os.Stat(e.path); err != nil {
		t.Fatalf("auth.json not written after register+flush: %v", err)
	}

	// Reload into fresh stores: the SCRAM verifier survived, so the first-write-only
	// guard still fires (409) — persistence preserves the invariant across restart.
	e2 := newEnv(t, dir)
	if code := e2.postRegister(t, a); code != http.StatusConflict {
		t.Fatalf("re-register after reload: status %d, want 409 (cred should have survived)", code)
	}
}

// ---- the core fix: a token survives a restart ----

func TestPersist_RestartSurvival_TokenAuthenticates(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, dir)
	a, d := acct(0x11), dev(0x01)
	tokHex := e.enroll(t, a, d)
	tok, _ := hex.DecodeString(tokHex)

	// Fresh stores loaded from the same auth.json (a "restart").
	reg2 := auth.NewRegistry()
	tokens2 := auth.NewTokenStore(reg2)
	h2 := authapi.New(reg2, tokens2)
	if _, err := Wire(reg2, tokens2, h2, e.path); err != nil {
		t.Fatalf("reload Wire: %v", err)
	}
	sess, err := tokens2.AuthenticateSession(ids.DeviceToken(tok))
	if err != nil {
		t.Fatalf("token did NOT survive restart: %v", err)
	}
	if sess.Account != a || sess.Device != d {
		t.Fatalf("reloaded session binds wrong (account/device) pair")
	}
	if rec, ok := reg2.Get(a, d); !ok || !rec.Approved || rec.Retired {
		t.Fatalf("device record did not survive: %+v ok=%v", rec, ok)
	}
}

// ---- absent file vs corrupt file ----

func TestPersist_FirstBootNoFile_StartsEmpty(t *testing.T) {
	dir := t.TempDir() // no auth.json present (the deployed-VPS shape)
	reg := auth.NewRegistry()
	tokens := auth.NewTokenStore(reg)
	h := authapi.New(reg, tokens)
	if _, err := Wire(reg, tokens, h, filepath.Join(dir, "auth.json")); err != nil {
		t.Fatalf("absent auth.json must start empty, got error: %v", err)
	}
	if len(reg.DeviceSnapshot()) != 0 || len(tokens.TokenSnapshot()) != 0 || len(h.CredSnapshot()) != 0 {
		t.Fatal("absent-file load should yield empty stores")
	}
}

func TestPersist_CorruptFile_FailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"garbage", "this is not json at all \x00\x01"},
		{"truncated", `{"version":1,"devices":[{`},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "auth.json")
			if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			reg := auth.NewRegistry()
			tokens := auth.NewTokenStore(reg)
			h := authapi.New(reg, tokens)
			_, err := Wire(reg, tokens, h, path)
			if err == nil {
				t.Fatalf("present-but-unparseable auth.json must fail closed, got nil error")
			}
			// The bounded error must not leak the path or any file bytes.
			if strings.Contains(err.Error(), path) || (tc.raw != "" && strings.Contains(err.Error(), tc.raw)) {
				t.Fatalf("fail-closed error leaked path/content: %q", err.Error())
			}
		})
	}
}

func TestPersist_VersionGuard_FailsClosedOnNewerSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(path, []byte(`{"version":999,"devices":[],"tokens":[],"creds":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := auth.NewRegistry()
	tokens := auth.NewTokenStore(reg)
	h := authapi.New(reg, tokens)
	if _, err := Wire(reg, tokens, h, path); err == nil {
		t.Fatal("a newer-than-supported schema version must fail closed")
	}
}

// ---- referential integrity: a token whose device is absent must NOT authenticate ----

func TestPersist_TokenWithoutRegistryRecord_Rejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	a, d := acct(0x55), dev(0x05)
	tok := strings.Repeat("99", 32)
	env := envelope{
		Version: schemaVersion,
		Tokens:  []auth.PersistedToken{{TokenHex: tok, Account: a, Device: d}},
		Devices: nil, // no device record for (a,d)
	}
	raw, _ := json.Marshal(env)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	reg := auth.NewRegistry()
	tokens := auth.NewTokenStore(reg)
	h := authapi.New(reg, tokens)
	if _, err := Wire(reg, tokens, h, path); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	tokBytes, _ := hex.DecodeString(tok)
	if _, err := tokens.AuthenticateSession(ids.DeviceToken(tokBytes)); err == nil {
		t.Fatal("a token with no backing registry record must be REJECTED (fail-closed), not accepted")
	}
}

func TestPersist_RetiredDeviceRejectedAfterReload(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, dir)
	a, d := acct(0x21), dev(0x02)
	tokHex := e.enroll(t, a, d)
	_ = e.reg.Retire(a, d)
	e.coord.Save()

	reg2 := auth.NewRegistry()
	tokens2 := auth.NewTokenStore(reg2)
	h2 := authapi.New(reg2, tokens2)
	if _, err := Wire(reg2, tokens2, h2, e.path); err != nil {
		t.Fatal(err)
	}
	tok, _ := hex.DecodeString(tokHex)
	if _, err := tokens2.AuthenticateSession(ids.DeviceToken(tok)); err == nil {
		t.Fatal("a retired device's token must be rejected after reload (Retired round-tripped true)")
	}
}

// ---- idempotency, perms, no-stale-temp ----

func TestPersist_DoubleLoadIdempotent(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, dir)
	a, d := acct(0x31), dev(0x03)
	e.enroll(t, a, d)

	reg2 := auth.NewRegistry()
	tokens2 := auth.NewTokenStore(reg2)
	h2 := authapi.New(reg2, tokens2)
	c2, err := Wire(reg2, tokens2, h2, e.path)
	if err != nil {
		t.Fatal(err)
	}
	first := tokens2.TokenSnapshot()
	if err := c2.load(); err != nil { // second load
		t.Fatal(err)
	}
	second := tokens2.TokenSnapshot()
	if len(first) != 1 || len(second) != 1 || first[0].TokenHex != second[0].TokenHex {
		t.Fatalf("double-load not idempotent: minted/changed a token (%d then %d)", len(first), len(second))
	}
}

func TestPersist_FilePermsAndNoStaleTemp(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, dir)
	e.enroll(t, acct(0x41), dev(0x04))
	e.postRegister(t, acct(0x41))

	info, err := os.Stat(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("auth.json perms = %o, want 0600 (holds tokens + SCRAM verifiers)", perm)
	}
	ents, _ := os.ReadDir(dir)
	for _, ent := range ents {
		if strings.HasPrefix(ent.Name(), ".tmp") {
			t.Fatalf("stale temp file left beside auth.json: %s", ent.Name())
		}
	}
}

// ---- concurrency: mutate + save from many goroutines, then reload consistent ----

func TestPersist_ConcurrentMutateAndSave_RaceCleanAndConsistent(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, dir)
	const n = 24
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// distinct account+device per goroutine; enroll mutates reg+tokens + saves
			e.enroll(t, acct(byte(0x80+i)), dev(byte(0x80+i)))
		}(i)
	}
	close(start)
	wg.Wait()

	// Reload and assert cross-store referential integrity: every persisted token has a
	// matching, non-retired device record (no torn snapshot).
	reg2 := auth.NewRegistry()
	tokens2 := auth.NewTokenStore(reg2)
	h2 := authapi.New(reg2, tokens2)
	if _, err := Wire(reg2, tokens2, h2, e.path); err != nil {
		t.Fatal(err)
	}
	toks := tokens2.TokenSnapshot()
	if len(toks) != n {
		t.Fatalf("reloaded %d tokens, want %d (lost/torn save)", len(toks), n)
	}
	for _, pt := range toks {
		if rec, ok := reg2.Get(pt.Account, pt.Device); !ok || rec.Retired {
			t.Fatalf("token has no live registry record after reload (torn cross-store snapshot)")
		}
	}
}

// ---- all three stores round-trip byte-for-byte ----

func TestPersist_AllThreeStoresRoundTrip(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, dir)
	a, d := acct(0x61), dev(0x06)
	e.enroll(t, a, d)
	// add a known SCRAM verifier and persist
	salt, sk, srk := []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}, []byte{9, 10, 11, 12}
	e.h.LoadCreds([]authapi.PersistedCred{{Account: a, Username: "rt", Salt: salt, Iterations: 7, StoredKey: sk, ServerKey: srk}})
	e.coord.Save()

	reg2 := auth.NewRegistry()
	tokens2 := auth.NewTokenStore(reg2)
	h2 := authapi.New(reg2, tokens2)
	if _, err := Wire(reg2, tokens2, h2, e.path); err != nil {
		t.Fatal(err)
	}
	creds := h2.CredSnapshot()
	if len(creds) != 1 {
		t.Fatalf("reloaded %d creds, want 1", len(creds))
	}
	c := creds[0]
	if c.Account != a || c.Username != "rt" || c.Iterations != 7 ||
		!bytes.Equal(c.Salt, salt) || !bytes.Equal(c.StoredKey, sk) || !bytes.Equal(c.ServerKey, srk) {
		t.Fatalf("SCRAM verifier did not round-trip byte-for-byte: %+v", c)
	}
}

// ---- the GC must NOT mass-retire restored devices (LastActivity == 0) ----

func TestPersist_GCDoesNotRetireRestoredDevices(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, dir)
	a := acct(0x71)
	for i := byte(1); i <= 5; i++ {
		e.enroll(t, a, dev(i))
	}
	// Reload (all devices come back with LastActivity == 0).
	reg2 := auth.NewRegistry()
	tokens2 := auth.NewTokenStore(reg2)
	h2 := authapi.New(reg2, tokens2)
	if _, err := Wire(reg2, tokens2, h2, e.path); err != nil {
		t.Fatal(err)
	}
	st := store.NewMemStore()
	gc := gcquota.NewHorizonGC(st, reg2, gcquota.DefaultPolicy())
	// A large current marker (days since epoch) makes cutoff > 0; LastActivity==0
	// must NOT be treated as past-horizon.
	_, retired := gc.Run(a, 99999)
	if retired != 0 {
		t.Fatalf("GC soft-retired %d restored devices (LastActivity==0 must be 'unseen', not stale)", retired)
	}
	for i := byte(1); i <= 5; i++ {
		if rec, ok := reg2.Get(a, dev(i)); !ok || rec.Retired {
			t.Fatalf("device %d was retired by the post-restart GC sweep", i)
		}
	}
}
