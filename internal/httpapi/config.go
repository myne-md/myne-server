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

	// Pre-auth abuse bounds (DoS hardening). PreAuthBurst/Refill drive the single
	// global pre-auth token bucket (account/IP-independent by construction, C4/AS14).
	// MaxAccounts/MaxHandshakes/HandshakeTTLSeconds cap + expire the auth maps.
	// MaxAttachmentsPerVault caps the attachment id count per vault. Unlike the quota
	// ceiling (0=unlimited by convention), these ship as FINITE safety-net defaults so
	// a default deployment is not defenceless; an operator raises them via env.
	PreAuthBurst           uint64
	PreAuthRefill          uint64
	MaxAccounts            uint64 // 0 = unlimited (opt-out)
	MaxHandshakes          uint64 // 0 = unlimited (opt-out)
	HandshakeTTLSeconds    uint64 // 0 = handshakes never expire (opt-out)
	MaxAttachmentsPerVault uint64 // 0 = unlimited (opt-out)

	// Built-in encrypted off-box backup (MYNE_BACKUP_*, MYND-505). Disabled by
	// default. When enabled, the server drives a bundled restic to snapshot the fs
	// store to an off-box target on a schedule. Only meaningful on the fs backend —
	// mem has no on-disk tree. Confidentiality is unchanged (blobs are already
	// client-encrypted, TB5/§6); the backup encryption's load-bearing job is
	// auth.json plus bounding retention. Retention (days) is the disclosed window
	// (threat-model §7 / self-host-policy §3); widening it re-discloses.
	BackupEnabled         bool   // MYNE_BACKUP_ENABLED; default false
	BackupIntervalSeconds uint64 // MYNE_BACKUP_INTERVAL_SECONDS; scheduler tick
	BackupRepository      string // MYNE_BACKUP_REPOSITORY; restic repo URI
	BackupPasswordFile    string // MYNE_BACKUP_PASSWORD_FILE; restic repo key file (never on argv)
	BackupRetentionDays   uint64 // MYNE_BACKUP_RETENTION_DAYS; disclosed bound, default 14
	BackupRcloneConfig    string // MYNE_BACKUP_RCLONE_CONFIG; SFTP transport config (Task 6)
	// Image-internal wiring (not operator policy): the bundled restic path + a
	// writable cache dir. The container image sets these in ENV; an operator tunes
	// the knobs above (repository/retention/interval), not these.
	BackupResticBin string // MYNE_BACKUP_RESTIC_BIN; path to bundled restic, default "restic" (PATH)
	BackupCacheDir  string // MYNE_BACKUP_CACHE_DIR; RESTIC_CACHE_DIR (writable for the runtime UID)
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
		PreAuthBurst:           64,
		PreAuthRefill:          8,
		MaxAccounts:            1_000_000,
		MaxHandshakes:          16384,
		HandshakeTTLSeconds:    60,
		MaxAttachmentsPerVault: 100_000,
		BackupIntervalSeconds:  86400,    // daily
		BackupRetentionDays:    14,       // disclosed off-box window
		BackupResticBin:        "restic", // resolved on PATH by default
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

	if cfg.PreAuthBurst, err = uintEnv("MYNE_PREAUTH_RATELIMIT_BURST", cfg.PreAuthBurst); err != nil {
		return Config{}, err
	}
	if cfg.PreAuthRefill, err = uintEnv("MYNE_PREAUTH_RATELIMIT_REFILL", cfg.PreAuthRefill); err != nil {
		return Config{}, err
	}
	if cfg.MaxAccounts, err = uintEnv("MYNE_MAX_ACCOUNTS", cfg.MaxAccounts); err != nil {
		return Config{}, err
	}
	if cfg.MaxHandshakes, err = uintEnv("MYNE_MAX_HANDSHAKES", cfg.MaxHandshakes); err != nil {
		return Config{}, err
	}
	if cfg.HandshakeTTLSeconds, err = uintEnv("MYNE_HANDSHAKE_TTL_SECONDS", cfg.HandshakeTTLSeconds); err != nil {
		return Config{}, err
	}
	if cfg.MaxAttachmentsPerVault, err = uintEnv("MYNE_MAX_ATTACHMENTS_PER_VAULT", cfg.MaxAttachmentsPerVault); err != nil {
		return Config{}, err
	}

	// A pre-auth burst of 0 would reject every registration/handshake, locking out
	// enrollment entirely — refuse to start rather than serve a dead auth surface.
	if cfg.PreAuthBurst == 0 {
		return Config{}, fmt.Errorf("MYNE_PREAUTH_RATELIMIT_BURST must be > 0 (0 rejects all pre-auth requests, locking out enrollment)")
	}

	// Backup config (MYND-505). Read unconditionally; enforce only when enabled so a
	// disabled server ignores half-set backup vars and starts exactly as before.
	if b, ok, e := boolEnv("MYNE_BACKUP_ENABLED"); e != nil {
		return Config{}, e
	} else if ok {
		cfg.BackupEnabled = b
	}
	cfg.BackupRepository = os.Getenv("MYNE_BACKUP_REPOSITORY")
	cfg.BackupPasswordFile = os.Getenv("MYNE_BACKUP_PASSWORD_FILE")
	cfg.BackupRcloneConfig = os.Getenv("MYNE_BACKUP_RCLONE_CONFIG")
	cfg.BackupResticBin = envOr("MYNE_BACKUP_RESTIC_BIN", cfg.BackupResticBin)
	cfg.BackupCacheDir = os.Getenv("MYNE_BACKUP_CACHE_DIR")
	if cfg.BackupIntervalSeconds, err = uintEnv("MYNE_BACKUP_INTERVAL_SECONDS", cfg.BackupIntervalSeconds); err != nil {
		return Config{}, err
	}
	if cfg.BackupRetentionDays, err = uintEnv("MYNE_BACKUP_RETENTION_DAYS", cfg.BackupRetentionDays); err != nil {
		return Config{}, err
	}
	if cfg.BackupEnabled {
		// Backup snapshots the on-disk store tree; mem has none.
		if cfg.StorageBackend != "fs" {
			return Config{}, fmt.Errorf("MYNE_BACKUP_ENABLED requires MYNE_STORAGE_BACKEND=fs (mem has no on-disk store to back up)")
		}
		if cfg.BackupRepository == "" {
			return Config{}, fmt.Errorf("MYNE_BACKUP_ENABLED requires MYNE_BACKUP_REPOSITORY")
		}
		if cfg.BackupPasswordFile == "" {
			return Config{}, fmt.Errorf("MYNE_BACKUP_ENABLED requires MYNE_BACKUP_PASSWORD_FILE")
		}
		if cfg.BackupIntervalSeconds == 0 {
			return Config{}, fmt.Errorf("MYNE_BACKUP_INTERVAL_SECONDS must be > 0 when backup is enabled")
		}
		// A 0-day retention would prune every snapshot on the same run that took it.
		if cfg.BackupRetentionDays == 0 {
			return Config{}, fmt.Errorf("MYNE_BACKUP_RETENTION_DAYS must be > 0 when backup is enabled")
		}
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
