// SPDX-License-Identifier: AGPL-3.0-only

package httpapi

import "testing"

// enableBackupEnv sets a complete, valid backup env on an fs backend so an
// individual test can then unset/override exactly one field to exercise one
// fail-fast rule in isolation.
func enableBackupEnv(t *testing.T) {
	t.Helper()
	t.Setenv("MYNE_STORAGE_BACKEND", "fs")
	t.Setenv("MYNE_STORAGE_PATH", t.TempDir())
	t.Setenv("MYNE_BACKUP_ENABLED", "true")
	t.Setenv("MYNE_BACKUP_REPOSITORY", "sftp:u1@u1.your-storagebox.de:/backups/myne")
	t.Setenv("MYNE_BACKUP_PASSWORD_FILE", "/etc/myne/restic.pass")
	// INTERVAL/RETENTION left at their non-zero defaults.
}

// TestBackup_DisabledByDefault: no MYNE_BACKUP_* env → backup off, its fields
// carry documented defaults, and nothing about startup changes.
func TestBackup_DisabledByDefault(t *testing.T) {
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.BackupEnabled {
		t.Errorf("backup enabled by default; want disabled")
	}
	if cfg.BackupRetentionDays != 14 {
		t.Errorf("default retention = %d, want 14", cfg.BackupRetentionDays)
	}
	if cfg.BackupResticBin != "restic" {
		t.Errorf("default restic bin = %q, want restic", cfg.BackupResticBin)
	}
}

// TestBackup_ValidEnabledParses: a complete enabled config on fs parses clean.
func TestBackup_ValidEnabledParses(t *testing.T) {
	enableBackupEnv(t)
	t.Setenv("MYNE_BACKUP_INTERVAL_SECONDS", "3600")
	t.Setenv("MYNE_BACKUP_RETENTION_DAYS", "14")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !cfg.BackupEnabled {
		t.Errorf("backup should be enabled")
	}
	if cfg.BackupRepository == "" || cfg.BackupPasswordFile == "" {
		t.Errorf("repo/password not populated: %q / %q", cfg.BackupRepository, cfg.BackupPasswordFile)
	}
	if cfg.BackupIntervalSeconds != 3600 {
		t.Errorf("interval = %d, want 3600", cfg.BackupIntervalSeconds)
	}
	if cfg.BackupRetentionDays != 14 {
		t.Errorf("retention = %d, want 14", cfg.BackupRetentionDays)
	}
}

// TestBackup_EnabledMissingRepoFails: enabled without a repository is fatal.
func TestBackup_EnabledMissingRepoFails(t *testing.T) {
	enableBackupEnv(t)
	t.Setenv("MYNE_BACKUP_REPOSITORY", "")
	if _, err := loadConfig(); err == nil {
		t.Fatalf("expected fail-fast: backup enabled without a repository")
	}
}

// TestBackup_EnabledMissingPasswordFails: enabled without a password file is fatal.
func TestBackup_EnabledMissingPasswordFails(t *testing.T) {
	enableBackupEnv(t)
	t.Setenv("MYNE_BACKUP_PASSWORD_FILE", "")
	if _, err := loadConfig(); err == nil {
		t.Fatalf("expected fail-fast: backup enabled without a password file")
	}
}

// TestBackup_EnabledOnMemBackendFails: backup only means anything on the fs
// backend (mem has no on-disk tree to snapshot). Enabling it on mem is fatal.
func TestBackup_EnabledOnMemBackendFails(t *testing.T) {
	// Deliberately NOT fs — default mem backend.
	t.Setenv("MYNE_BACKUP_ENABLED", "true")
	t.Setenv("MYNE_BACKUP_REPOSITORY", "sftp:u1@host:/b")
	t.Setenv("MYNE_BACKUP_PASSWORD_FILE", "/etc/myne/restic.pass")
	if _, err := loadConfig(); err == nil {
		t.Fatalf("expected fail-fast: backup enabled on mem backend")
	}
}

// TestBackup_EnabledZeroIntervalFails: a 0 interval would never fire.
func TestBackup_EnabledZeroIntervalFails(t *testing.T) {
	enableBackupEnv(t)
	t.Setenv("MYNE_BACKUP_INTERVAL_SECONDS", "0")
	if _, err := loadConfig(); err == nil {
		t.Fatalf("expected fail-fast: zero backup interval")
	}
}

// TestBackup_EnabledZeroRetentionFails: a 0 retention would prune every snapshot.
func TestBackup_EnabledZeroRetentionFails(t *testing.T) {
	enableBackupEnv(t)
	t.Setenv("MYNE_BACKUP_RETENTION_DAYS", "0")
	if _, err := loadConfig(); err == nil {
		t.Fatalf("expected fail-fast: zero backup retention")
	}
}

// TestBackup_DisabledIgnoresIncompleteConfig: with backup off, half-set backup
// vars are ignored — they never block startup.
func TestBackup_DisabledIgnoresIncompleteConfig(t *testing.T) {
	t.Setenv("MYNE_BACKUP_ENABLED", "false")
	t.Setenv("MYNE_BACKUP_REPOSITORY", "") // incomplete, but disabled → ignored
	if _, err := loadConfig(); err != nil {
		t.Fatalf("disabled backup should ignore incomplete config, got: %v", err)
	}
}
