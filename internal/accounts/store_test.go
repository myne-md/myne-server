// SPDX-License-Identifier: AGPL-3.0-only

package accounts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func acct(b byte) ids.AccountNumberHash {
	var h ids.AccountNumberHash
	h[0] = b
	return h
}

func TestStore_AbsentAccountIsDefault(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "accounts.json"))
	if got := s.Get(acct(1)); !got.IsDefault() {
		t.Errorf("absent account should be all-defaults, got %+v", got)
	}
}

func TestStore_SparseRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s := New(path)
	s.Update(acct(0xAB), func(p *Policy) { p.Frozen = true; p.QuotaOverrideBytes = 1 << 20 })
	s.Flush()

	// Reload into a fresh store.
	s2 := New(path)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := s2.Get(acct(0xAB))
	if !got.Frozen || got.QuotaOverrideBytes != 1<<20 {
		t.Errorf("round-trip policy = %+v, want frozen + 1MiB override", got)
	}
	// An untouched account stays default after reload.
	if !s2.Get(acct(0x02)).IsDefault() {
		t.Errorf("untouched account should be default after reload")
	}
}

func TestStore_ClearingBecomesSparse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s := New(path)
	s.Update(acct(1), func(p *Policy) { p.Frozen = true })
	s.Update(acct(1), func(p *Policy) { p.Frozen = false }) // back to default → entry dropped
	s.Flush()

	raw, _ := os.ReadFile(path)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(env.Accounts) != 0 {
		t.Errorf("cleared account should leave NO entry (sparse), got %d entries", len(env.Accounts))
	}
}

func TestStore_SchemaVersionWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s := New(path)
	s.Update(acct(1), func(p *Policy) { p.MaxDevicesOverride = 5 })
	s.Flush()
	raw, _ := os.ReadFile(path)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Version != schemaVersion {
		t.Errorf("version = %d, want %d", env.Version, schemaVersion)
	}
}

func TestStore_TooNewFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	if err := os.WriteFile(path, []byte(`{"version":99,"accounts":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(path)
	if err := s.Load(); err == nil {
		t.Fatalf("a too-new accounts.json must fail closed")
	}
}

func TestStore_CorruptFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	if err := os.WriteFile(path, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := New(path).Load(); err == nil {
		t.Fatalf("a corrupt accounts.json must fail closed")
	}
}

func TestStore_AbsentFileIsFirstBoot(t *testing.T) {
	// Load on a path that does not exist → no error, empty store.
	s := New(filepath.Join(t.TempDir(), "nope.json"))
	if err := s.Load(); err != nil {
		t.Fatalf("absent file should be first-boot (nil), got %v", err)
	}
	if len(s.m) != 0 {
		t.Errorf("first-boot store should be empty")
	}
}

func TestStore_FlusherCoalesces(t *testing.T) {
	writes := 0
	s := New(filepath.Join(t.TempDir(), "accounts.json"))
	s.write = func(string, []byte) error { writes++; return nil }

	// Three mutations, then ONE flush → exactly one physical write (coalesced).
	s.Update(acct(1), func(p *Policy) { p.Frozen = true })
	s.Update(acct(2), func(p *Policy) { p.QuotaOverrideBytes = 10 })
	s.Update(acct(3), func(p *Policy) { p.MaxDevicesOverride = 3 })
	s.Flush()
	if writes != 1 {
		t.Fatalf("coalesced writes = %d, want 1", writes)
	}
	// No pending mutation → a second flush writes nothing.
	s.Flush()
	if writes != 1 {
		t.Fatalf("idle flush wrote again: writes = %d, want 1", writes)
	}
}

func TestStore_EffectiveHelpers(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "accounts.json"))
	s.Update(acct(1), func(p *Policy) {
		p.Frozen = true
		p.QuotaOverrideBytes = 500
		p.MaxDevicesOverride = 3
	})

	// Overridden account: the override wins over the base.
	if !s.Frozen(acct(1)) {
		t.Errorf("acct1 should be frozen")
	}
	if got := s.EffectiveQuota(acct(1), 1000); got != 500 {
		t.Errorf("effective quota = %d, want the override 500", got)
	}
	if got := s.EffectiveMaxDevices(acct(1), 10); got != 3 {
		t.Errorf("effective max devices = %d, want the override 3", got)
	}

	// Default account: falls back to base.
	if s.Frozen(acct(2)) {
		t.Errorf("acct2 should not be frozen")
	}
	if got := s.EffectiveQuota(acct(2), 1000); got != 1000 {
		t.Errorf("effective quota = %d, want the base 1000", got)
	}
	if got := s.EffectiveMaxDevices(acct(2), 10); got != 10 {
		t.Errorf("effective max devices = %d, want the base 10", got)
	}
}

func TestStore_DeleteRemovesEntry(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "accounts.json"))
	s.Update(acct(1), func(p *Policy) { p.Frozen = true })
	s.Delete(acct(1))
	if !s.Get(acct(1)).IsDefault() {
		t.Errorf("deleted account should be default")
	}
	if len(s.m) != 0 {
		t.Errorf("store should be empty after delete")
	}
}
