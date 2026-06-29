// SPDX-License-Identifier: AGPL-3.0

package httpapi

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/myne-md/myne-server/internal/gcquota"
	"github.com/myne-md/myne-server/internal/store"
)

// Config is the operator-tunable policy surface (MYND-438, SYNC-23). It is read
// from env vars (the self-host bundle sets them in docker-compose) and replaces
// the formerly-hardcoded rate-limit/quota knobs. The horizon floor is enforced by
// gcquota.Policy.Clamp() — config can never weaken the GC horizon below the safety
// margin. None of these knobs can weaken the zero-knowledge protocol (TB5/§6):
// they bound storage and abuse, not confidentiality.
type Config struct {
	StorageBackend  string // "mem" (default) | "fs"
	StoragePath     string // required when StorageBackend == "fs"
	RateLimitBurst  uint64
	RateLimitRefill uint64
	Policy          gcquota.Policy // QuotaCeilingBytes (0=unlimited) + HorizonMarkers (clamped) + ExtendedRetention
	MetricsAddr     string         // MYNE_METRICS_ADDR; "" = disabled. Bind to localhost/internal only — NEVER the public edge.
}

// loadConfig reads the MYNE_* env vars and fails fast on any invalid value, so a
// misconfigured server never starts in a surprising state. Absent vars fall back
// to the documented defaults (mem backend, 256/16 rate-limit, unlimited quota,
// 120-marker horizon).
func loadConfig() (Config, error) {
	cfg := Config{
		StorageBackend:  strings.ToLower(envOr("MYNE_STORAGE_BACKEND", "mem")),
		StoragePath:     os.Getenv("MYNE_STORAGE_PATH"),
		MetricsAddr:     os.Getenv("MYNE_METRICS_ADDR"),
		RateLimitBurst:  256,
		RateLimitRefill: 16,
		Policy: gcquota.Policy{
			HorizonMarkers:    gcquota.DefaultHorizonMarkers,
			QuotaCeilingBytes: 0, // unlimited until set (SYNC-23)
		},
	}

	if cfg.StorageBackend != "mem" && cfg.StorageBackend != "fs" {
		return Config{}, fmt.Errorf("MYNE_STORAGE_BACKEND must be \"mem\" or \"fs\", got %q", cfg.StorageBackend)
	}
	if cfg.StorageBackend == "fs" && cfg.StoragePath == "" {
		return Config{}, fmt.Errorf("MYNE_STORAGE_BACKEND=fs requires MYNE_STORAGE_PATH")
	}

	var err error
	if cfg.RateLimitBurst, err = uintEnv("MYNE_RATELIMIT_BURST", cfg.RateLimitBurst); err != nil {
		return Config{}, err
	}
	if cfg.RateLimitRefill, err = uintEnv("MYNE_RATELIMIT_REFILL", cfg.RateLimitRefill); err != nil {
		return Config{}, err
	}
	if cfg.Policy.QuotaCeilingBytes, err = uintEnv("MYNE_QUOTA_CEILING_BYTES", cfg.Policy.QuotaCeilingBytes); err != nil {
		return Config{}, err
	}
	if cfg.Policy.HorizonMarkers, err = uintEnv("MYNE_HORIZON_MARKERS", cfg.Policy.HorizonMarkers); err != nil {
		return Config{}, err
	}
	if b, ok, e := boolEnv("MYNE_EXTENDED_RETENTION"); e != nil {
		return Config{}, e
	} else if ok {
		cfg.Policy.ExtendedRetention = b
	}

	// Clamp is the SINGLE floor-enforcement point: config cannot push the horizon
	// below MinHorizonMarkers (the Cassandra-zombie margin), no matter the env value.
	cfg.Policy = cfg.Policy.Clamp()
	return cfg, nil
}

// newStore builds the BlobStore named by the config. FS is durable single-volume
// (SYNC-22); mem is the dev/E2E reference.
func (c Config) newStore() (store.BlobStore, error) {
	switch c.StorageBackend {
	case "fs":
		return store.NewFSStore(c.StoragePath)
	default:
		return store.NewMemStore(), nil
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func uintEnv(key string, def uint64) (uint64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a non-negative integer, got %q", key, v)
	}
	return n, nil
}

func boolEnv(key string) (val, present bool, err error) {
	v := os.Getenv(key)
	if v == "" {
		return false, false, nil
	}
	b, e := strconv.ParseBool(v)
	if e != nil {
		return false, false, fmt.Errorf("%s must be a boolean, got %q", key, v)
	}
	return b, true, nil
}
