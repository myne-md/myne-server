// SPDX-License-Identifier: AGPL-3.0

package backup

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func sampleRunner() Runner {
	return Runner{
		ResticBin:     "restic",
		Repository:    "sftp:u1@u1.your-storagebox.de:/backups/myne",
		PasswordFile:  "/etc/myne/restic.pass",
		CacheDir:      "/var/cache/restic",
		RcloneConfig:  "/etc/myne/rclone.conf",
		RetentionDays: 14,
	}
}

func TestRunner_BackupArgs(t *testing.T) {
	got := sampleRunner().backupArgs("/data")
	want := []string{"backup", "--tag", "myne-sync", "/data"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("backupArgs = %v, want %v", got, want)
	}
}

func TestRunner_ForgetArgs_RetentionMapsToKeepWithin(t *testing.T) {
	got := sampleRunner().forgetArgs()
	want := []string{"forget", "--tag", "myne-sync", "--keep-within", "14d", "--prune"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("forgetArgs = %v, want %v", got, want)
	}
}

func TestRunner_RestoreArgs(t *testing.T) {
	got := sampleRunner().restoreArgs("latest", "/srv/restore")
	want := []string{"restore", "latest", "--target", "/srv/restore"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("restoreArgs = %v, want %v", got, want)
	}
}

func TestRunner_CheckArgs(t *testing.T) {
	if got := sampleRunner().checkArgs(); !reflect.DeepEqual(got, []string{"check"}) {
		t.Errorf("checkArgs = %v, want [check]", got)
	}
}

func TestRunner_CustomTagOverridesDefault(t *testing.T) {
	r := sampleRunner()
	r.Tag = "nightly"
	if got := r.backupArgs("/d"); got[2] != "nightly" {
		t.Errorf("backup tag = %q, want nightly", got[2])
	}
	if got := r.forgetArgs(); got[2] != "nightly" {
		t.Errorf("forget tag = %q, want nightly", got[2])
	}
}

func TestRunner_EnvCarriesResticSecretsNotArgv(t *testing.T) {
	env := sampleRunner().env()
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"RESTIC_REPOSITORY=sftp:u1@u1.your-storagebox.de:/backups/myne",
		"RESTIC_PASSWORD_FILE=/etc/myne/restic.pass",
		"RESTIC_CACHE_DIR=/var/cache/restic",
		"RCLONE_CONFIG=/etc/myne/rclone.conf",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("env missing %q", want)
		}
	}
	// Secrets must never appear on argv.
	for _, a := range sampleRunner().backupArgs("/data") {
		if strings.Contains(a, "restic.pass") || strings.Contains(a, "your-storagebox") {
			t.Errorf("secret leaked onto argv: %q", a)
		}
	}
}

func TestRunner_EnvOmitsEmptyOptionals(t *testing.T) {
	r := sampleRunner()
	r.CacheDir = ""
	r.RcloneConfig = ""
	joined := strings.Join(r.env(), "\n")
	if strings.Contains(joined, "RESTIC_CACHE_DIR=") {
		t.Errorf("empty cache dir should be omitted")
	}
	if strings.Contains(joined, "RCLONE_CONFIG=") {
		t.Errorf("empty rclone config should be omitted")
	}
}

// writeStubRestic writes a fake restic that appends each invocation's first arg
// (the subcommand) to a log file, then exits with the given code.
func writeStubRestic(t *testing.T, logPath string, exitCode int) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "restic-stub.sh")
	script := "#!/bin/sh\necho \"$1\" >> " + logPath + "\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	return bin
}

func TestRunner_BackupRunsBackupThenForget(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "calls.log")
	r := sampleRunner()
	r.ResticBin = writeStubRestic(t, logPath, 0)

	if err := r.Backup(context.Background(), "/data"); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if want := "backup\nforget\n"; string(got) != want {
		t.Errorf("call order = %q, want %q", got, want)
	}
}

func TestRunner_NonZeroExitSurfacesError(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "calls.log")
	r := sampleRunner()
	r.ResticBin = writeStubRestic(t, logPath, 3)

	err := r.Backup(context.Background(), "/data")
	if err == nil {
		t.Fatalf("expected error from non-zero restic exit")
	}
	if !strings.Contains(err.Error(), "restic backup") {
		t.Errorf("error should name the failing subcommand: %v", err)
	}
}
