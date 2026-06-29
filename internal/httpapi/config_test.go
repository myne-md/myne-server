// SPDX-License-Identifier: AGPL-3.0

package httpapi

import (
	"testing"

	"github.com/myne-md/myne-server/internal/gcquota"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

func TestConfig_Defaults(t *testing.T) {
	// No MYNE_* env set → documented defaults.
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.StorageBackend != "mem" {
		t.Errorf("default backend = %q, want mem", cfg.StorageBackend)
	}
	if cfg.RateLimitBurst != 256 || cfg.RateLimitRefill != 16 {
		t.Errorf("default rate-limit = %d/%d, want 256/16", cfg.RateLimitBurst, cfg.RateLimitRefill)
	}
	if cfg.Policy.QuotaCeilingBytes != 0 {
		t.Errorf("default quota = %d, want 0 (unlimited)", cfg.Policy.QuotaCeilingBytes)
	}
	if cfg.Policy.HorizonMarkers != gcquota.DefaultHorizonMarkers {
		t.Errorf("default horizon = %d, want %d", cfg.Policy.HorizonMarkers, gcquota.DefaultHorizonMarkers)
	}
}

func TestConfig_EnvPopulatesKnobs(t *testing.T) {
	t.Setenv("MYNE_RATELIMIT_BURST", "1000")
	t.Setenv("MYNE_RATELIMIT_REFILL", "50")
	t.Setenv("MYNE_QUOTA_CEILING_BYTES", "1073741824")
	t.Setenv("MYNE_HORIZON_MARKERS", "200")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.RateLimitBurst != 1000 || cfg.RateLimitRefill != 50 {
		t.Errorf("rate-limit = %d/%d, want 1000/50", cfg.RateLimitBurst, cfg.RateLimitRefill)
	}
	if cfg.Policy.QuotaCeilingBytes != 1073741824 {
		t.Errorf("quota = %d, want 1073741824", cfg.Policy.QuotaCeilingBytes)
	}
	if cfg.Policy.HorizonMarkers != 200 {
		t.Errorf("horizon = %d, want 200", cfg.Policy.HorizonMarkers)
	}
}

// TestConfig_HorizonClampFloor: config can NEVER push the horizon below the floor,
// no matter the env value (the single floor-enforcement point, SYNC-23).
func TestConfig_HorizonClampFloor(t *testing.T) {
	t.Setenv("MYNE_HORIZON_MARKERS", "5") // below MinHorizonMarkers (30)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Policy.HorizonMarkers != gcquota.MinHorizonMarkers {
		t.Fatalf("horizon not clamped: got %d, want floor %d", cfg.Policy.HorizonMarkers, gcquota.MinHorizonMarkers)
	}
}

func TestConfig_InvalidValueFailsFast(t *testing.T) {
	t.Setenv("MYNE_RATELIMIT_BURST", "not-a-number")
	if _, err := loadConfig(); err == nil {
		t.Fatalf("expected fail-fast on invalid rate-limit, got nil")
	}
}

func TestConfig_FSBackendRequiresPath(t *testing.T) {
	t.Setenv("MYNE_STORAGE_BACKEND", "fs")
	// MYNE_STORAGE_PATH intentionally unset.
	if _, err := loadConfig(); err == nil {
		t.Fatalf("expected error: fs backend without a path")
	}
}

func TestConfig_InvalidBackendFailsFast(t *testing.T) {
	t.Setenv("MYNE_STORAGE_BACKEND", "postgres")
	if _, err := loadConfig(); err == nil {
		t.Fatalf("expected error on unknown backend")
	}
}

func TestConfig_FSBackendBuildsStore(t *testing.T) {
	t.Setenv("MYNE_STORAGE_BACKEND", "fs")
	t.Setenv("MYNE_STORAGE_PATH", t.TempDir())
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	s, err := cfg.newStore()
	if err != nil || s == nil {
		t.Fatalf("newStore(fs): %v", err)
	}
}

// TestConfig_QuotaZeroIsUnlimited documents the intentional unlimited default (T4):
// a 0 ceiling never exceeds; a non-zero ceiling enforces.
func TestConfig_QuotaZeroIsUnlimited(t *testing.T) {
	s := store.NewMemStore()
	var a ids.AccountNumberHash
	a[0] = 1

	cfg, _ := loadConfig() // default ceiling 0
	qg := gcquota.NewQuotaGuard(cfg.Policy.QuotaCeilingBytes)
	if qg.WouldExceed(s, a, 1<<40) {
		t.Fatalf("quota=0 should be unlimited but flagged a large write as over-quota")
	}

	// A non-zero ceiling enforces.
	qg2 := gcquota.NewQuotaGuard(100)
	if !qg2.WouldExceed(s, a, 1000) {
		t.Fatalf("non-zero ceiling (100) should flag a 1000-byte write as over-quota")
	}
}
