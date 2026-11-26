// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// seedV1Store builds a v1 store dir with one blob + version marker, returns its root.
func seedV1Store(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	s, err := NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBlob(acct(1), blob(1), []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := writeStoreVersion(dir, 1); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestMigrate_FreshStoreAdoptsCurrentVersion(t *testing.T) {
	dir := t.TempDir()
	if err := NewMigrator(dir).Run(); err != nil {
		t.Fatalf("Run on fresh: %v", err)
	}
	v, present, err := readStoreVersion(dir)
	if err != nil || !present || v != CurrentStoreVersion {
		t.Fatalf("fresh store version = %d present=%v err=%v, want %d", v, present, err, CurrentStoreVersion)
	}
}

func TestMigrate_AlreadyCurrentIsNoop(t *testing.T) {
	dir := seedV1Store(t)
	m := &Migrator{root: dir, current: 1, migrations: nil}
	if err := m.Run(); err != nil {
		t.Fatalf("Run at current: %v", err)
	}
}

// TestMigrate_ForwardWithVerifiedSnapshot: a v1→v2 migration takes a verified
// snapshot, applies, and bumps the marker to 2.
func TestMigrate_ForwardWithVerifiedSnapshot(t *testing.T) {
	dir := seedV1Store(t)
	applied := false
	m := &Migrator{
		root:    dir,
		current: 2,
		migrations: []Migration{{To: 2, Apply: func(root string) error {
			applied = true
			// a trivial migration: drop a marker file (staging-rename discipline is
			// the migration's own responsibility; here we just prove Apply ran).
			return atomicWrite(filepath.Join(root, "migrated-to-v2"), []byte("ok"))
		}}},
	}
	if err := m.Run(); err != nil {
		t.Fatalf("Run v1->v2: %v", err)
	}
	if !applied {
		t.Fatal("migration Apply did not run")
	}
	if v, _, _ := readStoreVersion(dir); v != 2 {
		t.Fatalf("version not bumped: %d, want 2", v)
	}
	// A verified snapshot of the pre-migration (v1) state must exist and be restorable.
	snap := dir + ".premigrate-v1"
	if _, err := os.Stat(filepath.Join(snap, "store-version")); err != nil {
		t.Fatalf("pre-migration snapshot missing: %v", err)
	}
	if _, err := NewFSStore(snap); err != nil {
		t.Fatalf("snapshot not restorable: %v", err)
	}
}

// TestMigrate_DowngradeIsFailSafe: an older binary (current=1) seeing newer on-disk
// data (v2) must REFUSE — not silently mis-parse — and touch nothing.
func TestMigrate_DowngradeIsFailSafe(t *testing.T) {
	dir := seedV1Store(t)
	if err := writeStoreVersion(dir, 2); err != nil {
		t.Fatal(err)
	}
	m := &Migrator{root: dir, current: 1}
	err := m.Run()
	if err == nil {
		t.Fatal("expected fail-safe refusal on newer on-disk version, got nil")
	}
	if v, _, _ := readStoreVersion(dir); v != 2 {
		t.Fatalf("data version mutated on refusal: %d, want 2 untouched", v)
	}
}

// TestMigrate_ApplyFailureDoesNotBumpVersion: if Apply fails, the version marker
// stays at the OLD value (so the next boot re-runs from the snapshot) and the real
// store dir is not destroyed.
func TestMigrate_ApplyFailureDoesNotBumpVersion(t *testing.T) {
	dir := seedV1Store(t)
	m := &Migrator{
		root:    dir,
		current: 2,
		migrations: []Migration{{To: 2, Apply: func(root string) error {
			return errors.New("boom")
		}}},
	}
	if err := m.Run(); err == nil {
		t.Fatal("expected migration error, got nil")
	}
	if v, _, _ := readStoreVersion(dir); v != 1 {
		t.Fatalf("version bumped despite Apply failure: %d, want 1", v)
	}
	// The real store data survives (never deleted) + the snapshot exists for rollback.
	s, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("real store corrupted after failed migration: %v", err)
	}
	if got, _, err := s.GetBlob(acct(1), blob(1)); err != nil || string(got) != "payload" {
		t.Fatalf("real data lost after failed migration: %q err=%v", got, err)
	}
}

// TestMigrate_SkipSnapshotOverride: the explicit override skips the snapshot but
// still applies the migration.
func TestMigrate_SkipSnapshotOverride(t *testing.T) {
	dir := seedV1Store(t)
	m := &Migrator{
		root:         dir,
		current:      2,
		skipSnapshot: true,
		migrations:   []Migration{{To: 2, Apply: func(root string) error { return nil }}},
	}
	if err := m.Run(); err != nil {
		t.Fatalf("Run with skip-snapshot: %v", err)
	}
	if _, err := os.Stat(dir + ".premigrate-v1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot was taken despite skip override")
	}
	if v, _, _ := readStoreVersion(dir); v != 2 {
		t.Fatalf("migration did not apply under skip: version %d", v)
	}
}
