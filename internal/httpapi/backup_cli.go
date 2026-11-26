// SPDX-License-Identifier: AGPL-3.0-only

package httpapi

import (
	"context"
	"fmt"
	"log"

	"github.com/myne-md/myne-server/internal/backup"
	"github.com/myne-md/myne-server/internal/store"
)

// backupRunner builds a backup.Runner from the backup config. The scheduled path
// (MYND-505 Task 5) and the CLI path share this one construction.
func (c Config) backupRunner() backup.Runner {
	return backup.Runner{
		ResticBin:     c.BackupResticBin,
		Repository:    c.BackupRepository,
		PasswordFile:  c.BackupPasswordFile,
		CacheDir:      c.BackupCacheDir,
		RcloneConfig:  c.BackupRcloneConfig,
		RetentionDays: c.BackupRetentionDays,
	}
}

// BackupCLI runs a one-off backup subcommand from the process env and returns a
// process exit code (0 = success, non-zero = failure). It is what the main
// dispatch calls for `myne-server backup` / `backup-check` / `restore`.
//
// A manual backup command works whenever a repository + password file are set,
// independent of MYNE_BACKUP_ENABLED (that flag governs the automatic scheduler);
// an operator can always take an on-demand snapshot. `restore <dest-dir>
// [snapshot]` reconstructs a snapshot and verifies the restored tree opens.
func BackupCLI(ctx context.Context, sub string, args []string) int {
	cfg, err := loadConfig()
	if err != nil {
		log.Printf("backup: config error: %v", err)
		return 2
	}
	if cfg.BackupRepository == "" || cfg.BackupPasswordFile == "" {
		log.Printf("backup: MYNE_BACKUP_REPOSITORY and MYNE_BACKUP_PASSWORD_FILE are required")
		return 2
	}
	if cfg.StorageBackend != "fs" {
		log.Printf("backup: MYNE_STORAGE_BACKEND=fs is required (mem has no on-disk store to back up)")
		return 2
	}
	r := cfg.backupRunner()

	switch sub {
	case "backup":
		if err := r.Backup(ctx, cfg.StoragePath); err != nil {
			log.Printf("backup: %v", err)
			return 1
		}
	case "check":
		if err := r.Check(ctx); err != nil {
			log.Printf("backup-check: %v", err)
			return 1
		}
	case "restore":
		if len(args) < 1 {
			log.Printf("restore: usage: myne-server restore <dest-dir> [snapshot]")
			return 2
		}
		return backupRestore(ctx, cfg, r, args)
	default:
		log.Printf("backup: unknown subcommand %q", sub)
		return 2
	}
	return 0
}

// backupRestore restores a snapshot into destDir and verifies the reconstructed
// store opens with this binary. restic writes each file under destDir at its
// original absolute path, so the FSStore root lands at destDir + the storage
// path. WARNING to the operator: restoring an OLD snapshot can resurrect
// ciphertext that horizon-GC already reclaimed (see self-host-policy §3).
func backupRestore(ctx context.Context, cfg Config, r backup.Runner, args []string) int {
	destDir := args[0]
	snapshot := "latest"
	if len(args) > 1 {
		snapshot = args[1]
	}
	if err := r.Restore(ctx, snapshot, destDir); err != nil {
		log.Printf("restore: %v", err)
		return 1
	}
	restoredRoot := backup.RestoredRoot(destDir, cfg.StoragePath)
	if err := verifyRestoredStore(restoredRoot); err != nil {
		log.Printf("restore: verification failed: %v", err)
		return 1
	}
	log.Printf("restore: restored store verified at %s (restoring an old snapshot may revive horizon-GC-reclaimed ciphertext)", restoredRoot)
	return 0
}

// verifyRestoredStore proves a restored FSStore tree is bootable by this binary:
// store.OpenFS runs the migration fail-safe fence (a newer on-disk version is
// refused — SYNC-30, the "restore a backup" downgrade guard) then opens the tree.
// A restore that would mis-serve is worse than one that refuses.
func verifyRestoredStore(storePath string) error {
	if _, err := store.OpenFS(storePath); err != nil {
		return fmt.Errorf("restored store is not bootable: %w", err)
	}
	return nil
}
