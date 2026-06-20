// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CurrentStoreVersion is the on-disk FS-store layout version this binary writes
// and understands. Bump it (and register a Migration) whenever the on-disk format
// changes. The version marker makes a binary-downgrade FAIL-SAFE: an OLDER binary
// that sees a NEWER on-disk version refuses to start rather than silently
// mis-parsing it (SYNC-30) — so going back requires a snapshot restore.
const CurrentStoreVersion = 1

const storeVersionFile = "store-version"

// Migration transforms the on-disk store from version To-1 to version To. It MUST
// follow the staging-rename discipline: stage the migrated form, atomic-swap, and
// NEVER destroy the original until the new form verifies (the 2026-06-11 data-loss
// lesson — a side-effecting migration that deleted real vaults). The pre-migration
// snapshot is the rollback of last resort.
type Migration struct {
	To    int
	Apply func(root string) error
}

// Migrator runs forward-only on-disk migrations at boot, BEFORE the server listens
// (no concurrent writes → nothing to lose on rollback). "Rollback" = restore the
// verified pre-migration snapshot, never an in-place downgrade (a blind store
// cannot transform opaque ciphertext; only the metadata envelope could revert).
type Migrator struct {
	root         string
	current      int
	migrations   []Migration
	skipSnapshot bool
}

// NewMigrator builds the production migrator for a store root. MYNE_MIGRATE_SKIP_SNAPSHOT=1
// is the explicit, at-own-risk override for operators with their own backup strategy
// or a COW filesystem (snapshot is mandatory-by-default otherwise).
func NewMigrator(root string) *Migrator {
	skip, _ := strconv.ParseBool(os.Getenv("MYNE_MIGRATE_SKIP_SNAPSHOT"))
	return &Migrator{
		root:         root,
		current:      CurrentStoreVersion,
		migrations:   builtinMigrations, // empty at v1 — the framework + version marker are the deliverable
		skipSnapshot: skip,
	}
}

// builtinMigrations is the registered forward migration chain. Empty at v1 (the
// baseline). Append a Migration{To: 2, Apply: ...} when the format first changes.
var builtinMigrations []Migration

// Run brings the on-disk store up to CurrentStoreVersion. It is idempotent and safe
// to call on every boot. Order per migration: snapshot → VERIFY → apply → bump the
// version marker (only after apply succeeds, so a crash re-runs cleanly).
func (m *Migrator) Run() error {
	onDisk, present, err := readStoreVersion(m.root)
	if err != nil {
		return err
	}
	if !present {
		// Fresh (or pre-versioning) store: only one format has ever existed, so
		// adopt the current version and write the marker. No data is touched.
		return writeStoreVersion(m.root, m.current)
	}
	if onDisk == m.current {
		return nil
	}
	if onDisk > m.current {
		// FAIL-SAFE downgrade: an older binary must not touch newer-format data.
		return fmt.Errorf("store version %d is newer than this binary supports (max %d); upgrade the server or restore a backup", onDisk, m.current)
	}

	for _, mig := range m.migrations {
		if mig.To <= onDisk || mig.To > m.current {
			continue
		}
		if !m.skipSnapshot {
			snap, err := m.snapshot(onDisk)
			if err != nil {
				return fmt.Errorf("pre-migration snapshot failed, aborting (fail-closed): %w", err)
			}
			if err := verifySnapshot(snap); err != nil {
				return fmt.Errorf("pre-migration snapshot unverifiable, aborting (fail-closed): %w", err)
			}
		}
		if err := mig.Apply(m.root); err != nil {
			return fmt.Errorf("migration to v%d failed; rollback = restore the pre-migration snapshot: %w", mig.To, err)
		}
		// Bump the marker ONLY after Apply succeeds: a crash before this leaves the
		// old version on disk, so the next boot re-runs the migration from the snapshot.
		if err := writeStoreVersion(m.root, mig.To); err != nil {
			return err
		}
		onDisk = mig.To
	}
	return nil
}

// snapshot copies the whole store dir to a sibling pre-migration snapshot and
// returns its path. It NEVER touches the real store dir (the 2026-06-11 lesson). A
// COW filesystem (LVM/ZFS/btrfs) makes this near-instant; the portable default is a
// recursive copy. The snapshot is the rollback point.
func (m *Migrator) snapshot(fromVersion int) (string, error) {
	snap := m.root + fmt.Sprintf(".premigrate-v%d", fromVersion)
	if err := os.RemoveAll(snap); err != nil {
		return "", err
	}
	if err := copyTree(m.root, snap); err != nil {
		return "", err
	}
	return snap, nil
}

// verifySnapshot confirms the snapshot is restorable by re-opening it as a store
// (its index files must parse). A snapshot we cannot re-open is not a rollback point.
func verifySnapshot(snap string) error {
	_, err := NewFSStore(snap)
	return err
}

func readStoreVersion(root string) (version int, present bool, err error) {
	raw, err := os.ReadFile(filepath.Join(root, storeVersionFile))
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, false, fmt.Errorf("corrupt %s: %w", storeVersionFile, err)
	}
	return v, true, nil
}

func writeStoreVersion(root string, v int) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(root, storeVersionFile), []byte(strconv.Itoa(v)))
}

// copyTree recursively copies src to dst (files + dirs), used for the snapshot.
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
