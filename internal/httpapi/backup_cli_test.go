// SPDX-License-Identifier: AGPL-3.0-only

package httpapi

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// stubRestic writes a fake restic that logs each subcommand and exits with code.
func stubRestic(t *testing.T, logPath string, code int) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "restic-stub.sh")
	script := "#!/bin/sh\necho \"$1\" >> " + logPath + "\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	return bin
}

// configureBackupCLI sets a working fs + backup env pointing restic at a stub.
func configureBackupCLI(t *testing.T, stub string) {
	t.Helper()
	t.Setenv("MYNE_STORAGE_BACKEND", "fs")
	t.Setenv("MYNE_STORAGE_PATH", t.TempDir())
	t.Setenv("MYNE_BACKUP_REPOSITORY", "sftp:u1@host:/b")
	t.Setenv("MYNE_BACKUP_PASSWORD_FILE", filepath.Join(t.TempDir(), "pass"))
	t.Setenv("MYNE_BACKUP_RESTIC_BIN", stub)
}

func TestBackupCLI_UnconfiguredReturnsNonZero(t *testing.T) {
	// No repository/password set → clean non-zero, no panic.
	if code := BackupCLI(context.Background(), "backup", nil); code == 0 {
		t.Fatalf("unconfigured backup should return non-zero, got %d", code)
	}
}

func TestBackupCLI_MemBackendReturnsNonZero(t *testing.T) {
	t.Setenv("MYNE_BACKUP_REPOSITORY", "sftp:u1@host:/b")
	t.Setenv("MYNE_BACKUP_PASSWORD_FILE", "/etc/myne/pass")
	// backend left at mem default.
	if code := BackupCLI(context.Background(), "backup", nil); code == 0 {
		t.Fatalf("backup on mem backend should return non-zero, got %d", code)
	}
}

func TestBackupCLI_BackupRunsBackupThenForget(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls.log")
	configureBackupCLI(t, stubRestic(t, log, 0))
	if code := BackupCLI(context.Background(), "backup", nil); code != 0 {
		t.Fatalf("backup should succeed, got exit %d", code)
	}
	got, _ := os.ReadFile(log)
	if string(got) != "backup\nforget\n" {
		t.Errorf("calls = %q, want backup then forget", got)
	}
}

func TestBackupCLI_CheckRunsCheck(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls.log")
	configureBackupCLI(t, stubRestic(t, log, 0))
	if code := BackupCLI(context.Background(), "check", nil); code != 0 {
		t.Fatalf("check should succeed, got exit %d", code)
	}
	got, _ := os.ReadFile(log)
	if string(got) != "check\n" {
		t.Errorf("calls = %q, want check", got)
	}
}

func TestBackupCLI_ResticFailureReturnsOne(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls.log")
	configureBackupCLI(t, stubRestic(t, log, 3))
	if code := BackupCLI(context.Background(), "backup", nil); code != 1 {
		t.Fatalf("restic failure should return 1, got %d", code)
	}
}
