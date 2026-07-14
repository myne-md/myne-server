// SPDX-License-Identifier: AGPL-3.0

// Package backup drives a bundled restic binary to take encrypted, off-box,
// retention-bounded snapshots of the fs store (MYND-505). The server holds no
// keys; restic's repository key is an operator secret supplied via a password
// file. This package builds argv + RESTIC_* env and shells out — it hand-rolls
// no cryptography (restic owns the backup format), keeping the module pure-stdlib.
//
// Confidentiality is unchanged (blobs are already client-encrypted, TB5/§6). The
// backup encryption's load-bearing job is protecting auth.json and bounding how
// long a deleted blob survives off-box (retention window, threat-model §7).
package backup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// DefaultTag is the restic snapshot tag every myne-server backup carries, so
// `forget --tag` scopes retention to our snapshots and never touches a
// co-located repo's other snapshots.
const DefaultTag = "myne-sync"

// Runner shells out to restic. Every field is injected so a test can point
// ResticBin at a stub and assert the exact argv/env without a real restic.
type Runner struct {
	ResticBin     string // path to the restic binary
	Repository    string // RESTIC_REPOSITORY
	PasswordFile  string // RESTIC_PASSWORD_FILE (never on argv)
	CacheDir      string // RESTIC_CACHE_DIR (must be writable for the runtime UID)
	RcloneConfig  string // RCLONE_CONFIG for the rclone SFTP transport; "" = unused
	RetentionDays uint64 // forget --keep-within Nd
	Tag           string // snapshot tag; "" → DefaultTag
}

func (r Runner) tag() string {
	if r.Tag == "" {
		return DefaultTag
	}
	return r.Tag
}

// env returns the RESTIC_* (+ optional RCLONE_CONFIG) environment for a restic
// child, appended to the current process env. Secrets ride the env / password
// file, never argv.
func (r Runner) env() []string {
	e := append(os.Environ(),
		"RESTIC_REPOSITORY="+r.Repository,
		"RESTIC_PASSWORD_FILE="+r.PasswordFile,
	)
	if r.CacheDir != "" {
		e = append(e, "RESTIC_CACHE_DIR="+r.CacheDir)
	}
	if r.RcloneConfig != "" {
		e = append(e, "RCLONE_CONFIG="+r.RcloneConfig)
	}
	return e
}

func (r Runner) backupArgs(dataDir string) []string {
	return []string{"backup", "--tag", r.tag(), dataDir}
}

func (r Runner) forgetArgs() []string {
	keep := strconv.FormatUint(r.RetentionDays, 10) + "d"
	return []string{"forget", "--tag", r.tag(), "--keep-within", keep, "--prune"}
}

func (r Runner) restoreArgs(snapshot, destDir string) []string {
	return []string{"restore", snapshot, "--target", destDir}
}

// RestoredRoot reports where restic lands the store after `restore --target
// destDir`: restic recreates each file at its original absolute path, so the fs
// store root that was backed up at dataDir reappears at destDir + dataDir. Kept
// next to restoreArgs so all restic-layout knowledge stays in this package.
func RestoredRoot(destDir, dataDir string) string {
	return filepath.Join(destDir, dataDir)
}

func (r Runner) checkArgs() []string {
	return []string{"check"}
}

// exec runs restic with the given args, folding env + combined output into any
// error so a failure surfaces restic's own stderr to the operator.
func (r Runner) exec(ctx context.Context, args []string) error {
	cmd := exec.CommandContext(ctx, r.ResticBin, args...)
	cmd.Env = r.env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restic %s: %w: %s", args[0], err, out)
	}
	return nil
}

// Backup snapshots dataDir, then prunes to the retention window. A prune failure
// still surfaces even when the snapshot itself succeeded — a backup that cannot
// enforce its disclosed retention bound is not a clean success.
func (r Runner) Backup(ctx context.Context, dataDir string) error {
	if err := r.exec(ctx, r.backupArgs(dataDir)); err != nil {
		return err
	}
	return r.exec(ctx, r.forgetArgs())
}

// Restore reconstructs a snapshot into destDir. Caller verifies the tree opens.
func (r Runner) Restore(ctx context.Context, snapshot, destDir string) error {
	return r.exec(ctx, r.restoreArgs(snapshot, destDir))
}

// Check verifies repository integrity.
func (r Runner) Check(ctx context.Context) error {
	return r.exec(ctx, r.checkArgs())
}
