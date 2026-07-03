// SPDX-License-Identifier: AGPL-3.0

package httpapi

import "testing"

func TestConfig_PreAuthDefaults(t *testing.T) {
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.PreAuthBurst != 64 {
		t.Errorf("PreAuthBurst=%d, want 64", cfg.PreAuthBurst)
	}
	if cfg.PreAuthRefill != 8 {
		t.Errorf("PreAuthRefill=%d, want 8", cfg.PreAuthRefill)
	}
	if cfg.MaxAccounts != 1_000_000 {
		t.Errorf("MaxAccounts=%d, want 1000000", cfg.MaxAccounts)
	}
	if cfg.MaxHandshakes != 16384 {
		t.Errorf("MaxHandshakes=%d, want 16384", cfg.MaxHandshakes)
	}
	if cfg.HandshakeTTLSeconds != 60 {
		t.Errorf("HandshakeTTLSeconds=%d, want 60", cfg.HandshakeTTLSeconds)
	}
	if cfg.MaxAttachmentsPerVault != 100_000 {
		t.Errorf("MaxAttachmentsPerVault=%d, want 100000", cfg.MaxAttachmentsPerVault)
	}
}

func TestConfig_PreAuthEnvOverride(t *testing.T) {
	t.Setenv("MYNE_PREAUTH_RATELIMIT_BURST", "10")
	t.Setenv("MYNE_MAX_ACCOUNTS", "5")
	t.Setenv("MYNE_HANDSHAKE_TTL_SECONDS", "30")
	t.Setenv("MYNE_MAX_ATTACHMENTS_PER_VAULT", "42")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.PreAuthBurst != 10 || cfg.MaxAccounts != 5 || cfg.HandshakeTTLSeconds != 30 || cfg.MaxAttachmentsPerVault != 42 {
		t.Fatalf("env override mismatch: %+v", cfg)
	}
}

func TestConfig_PreAuthBurstZeroFailsFast(t *testing.T) {
	t.Setenv("MYNE_PREAUTH_RATELIMIT_BURST", "0")
	if _, err := loadConfig(); err == nil {
		t.Fatal("PreAuthBurst=0 must fail-fast (would lock out enrollment)")
	}
}
