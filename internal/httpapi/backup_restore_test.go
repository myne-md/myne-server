// SPDX-License-Identifier: AGPL-3.0

package httpapi

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/myne-md/myne-server/internal/store"
)

func TestVerifyRestoredStore_OpensValidTree(t *testing.T) {
	dir := t.TempDir()
	if _, err := store.NewFSStore(dir); err != nil { // seeds a valid current-version store
		t.Fatalf("seed store: %v", err)
	}
	if err := verifyRestoredStore(dir); err != nil {
		t.Errorf("a valid restored tree should verify, got: %v", err)
	}
}

func TestVerifyRestoredStore_RejectsFutureVersion(t *testing.T) {
	dir := t.TempDir()
	if _, err := store.NewFSStore(dir); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	// A newer on-disk version than this binary understands must fail the fence
	// (SYNC-30 fail-safe downgrade guard) — a "restore" that mis-serves is worse
	// than one that refuses.
	if err := os.WriteFile(filepath.Join(dir, "store-version"), []byte("99"), 0o644); err != nil {
		t.Fatalf("write version: %v", err)
	}
	if err := verifyRestoredStore(dir); err == nil {
		t.Errorf("a future store version should fail verification")
	}
}

func TestBackupCLI_RestoreMissingDestReturnsTwo(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls.log")
	configureBackupCLI(t, stubRestic(t, log, 0))
	if code := BackupCLI(context.Background(), "restore", nil); code != 2 {
		t.Fatalf("restore without a dest dir should return 2 (usage), got %d", code)
	}
}

// TestBackupCLI_RestoreRoundTrip is the real end-to-end restore proof: seed an
// FSStore, back it up to a local restic repo, restore it, and verify the tree
// opens. It needs a real restic (bundled into the image in Task 6); skipped when
// restic is not on PATH so the unit suite stays green on a bare dev box.
func TestBackupCLI_RestoreRoundTrip(t *testing.T) {
	resticBin, err := exec.LookPath("restic")
	if err != nil {
		t.Skip("restic not installed; skipping real restore round-trip (bundled in Task 6)")
	}

	dataDir := t.TempDir()
	if _, err := store.NewFSStore(dataDir); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	repo := t.TempDir()
	passFile := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(passFile, []byte("test-repo-key"), 0o600); err != nil {
		t.Fatalf("write pass: %v", err)
	}
	dest := t.TempDir()

	t.Setenv("MYNE_STORAGE_BACKEND", "fs")
	t.Setenv("MYNE_STORAGE_PATH", dataDir)
	t.Setenv("MYNE_BACKUP_REPOSITORY", "local:"+repo)
	t.Setenv("MYNE_BACKUP_PASSWORD_FILE", passFile)
	t.Setenv("MYNE_BACKUP_RESTIC_BIN", resticBin)

	// init repo, then backup + restore through the CLI.
	init := exec.Command(resticBin, "init")
	init.Env = append(os.Environ(), "RESTIC_REPOSITORY=local:"+repo, "RESTIC_PASSWORD_FILE="+passFile)
	if out, err := init.CombinedOutput(); err != nil {
		t.Fatalf("restic init: %v: %s", err, out)
	}
	if code := BackupCLI(context.Background(), "backup", nil); code != 0 {
		t.Fatalf("backup exit %d", code)
	}
	if code := BackupCLI(context.Background(), "restore", []string{dest}); code != 0 {
		t.Fatalf("restore exit %d", code)
	}
	// restic restores files under dest at their original absolute path, so the
	// store root lands at dest + dataDir. It must be byte-identical to the source.
	restored := filepath.Join(dest, dataDir)
	assertTreesEqual(t, dataDir, restored)
}

// assertTreesEqual fails if the two directory trees differ in structure or file
// bytes (used by the restic round-trip test to prove a byte-identical restore).
func assertTreesEqual(t *testing.T, want, got string) {
	t.Helper()
	rel := func(root, p string) string { r, _ := filepath.Rel(root, p); return r }
	seen := map[string][]byte{}
	if err := filepath.Walk(want, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		b, e := os.ReadFile(p)
		seen[rel(want, p)] = b
		return e
	}); err != nil {
		t.Fatalf("walk source: %v", err)
	}
	for name, wantBytes := range seen {
		gotBytes, err := os.ReadFile(filepath.Join(got, name))
		if err != nil {
			t.Errorf("restored tree missing %s: %v", name, err)
			continue
		}
		if string(gotBytes) != string(wantBytes) {
			t.Errorf("restored file %s differs from source", name)
		}
	}
}
