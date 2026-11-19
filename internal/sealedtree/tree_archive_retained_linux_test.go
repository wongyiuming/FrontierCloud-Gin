//go:build linux

package sealedtree

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

func checkRetainedTreeRestore(t *testing.T, ctx context.Context, base, material, archive, expected, node string, master []byte, directoryID string) {
	t.Helper()
	retained := filepath.Join(base, "retained-restore")
	if _, err := recovery.ApplyTreeStateArchive(ctx, archive, retained, expected, node); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(retained, "data")
	secrets := filepath.Join(base, "retained-secrets")
	if err := os.Rename(filepath.Join(retained, "runtime_secrets"), secrets); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"media/song.blob", "lyrics/song.lrc", "recordings/take.bin"} {
		path := filepath.Join(data, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	gate, err := maintenance.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	rebindArchive := func() (bool, error) {
		return RebindRetainedMasterTreeState(ctx, gate, archive, expected, material, data, secrets, "db.sqlite", node)
	}
	report, err := recovery.CheckTreeArchiveAuthenticated(ctx, archive, expected)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.CheckTreeMaterial(ctx, material, report); err != nil {
		t.Fatal(err)
	}
	rebind := func() (bool, error) {
		return RebindVerifiedRetainedMasterTreeState(ctx, gate, report.SHA256, report.Manifest, data, secrets, "db.sqlite", node)
	}
	root, err := os.OpenRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	checkIntent := func(want bool) {
		t.Helper()
		if got, err := RetainedTreeRebindIntentPresent(root); err != nil || got != want {
			t.Fatal("unexpected installer intent barrier", got, err)
		}
	}
	checkIntent(false)

	// A named but unauthenticated entry still blocks the host installer.
	if err := root.Symlink("absent-target", treeRebindIntentName); err != nil {
		t.Fatal(err)
	}
	checkIntent(true)
	if _, err := rebind(); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("linked intent accepted", err)
	}
	if err := root.Remove(treeRebindIntentName); err != nil {
		t.Fatal(err)
	}
	checkIntent(false)

	// A changed WAL must be rejected before SQLite gets a chance to replay it.
	wal := filepath.Join(data, "db.sqlite-wal")
	original, err := os.ReadFile(wal)
	if err != nil || len(original) == 0 {
		t.Fatal("expected retained WAL", err)
	}
	changed := append([]byte(nil), original...)
	changed[0] ^= 1
	if err := os.WriteFile(wal, changed, 0600); err != nil {
		t.Fatal(err)
	}
	before := recoverySQLiteFiles(t, data)
	if _, err := rebindArchive(); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("changed WAL accepted by archive wrapper", err)
	}
	if _, err := rebind(); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("changed WAL accepted by runtime wrapper", err)
	}
	assertRecoverySQLiteFilesUnchanged(t, data, before)
	checkIntent(false)
	if err := os.WriteFile(wal, original, 0600); err != nil {
		t.Fatal(err)
	}

	fenceDir := filepath.Join(data, MasterFenceDirectory)
	pins := make(map[string]os.FileInfo)
	for _, name := range []string{filepath.Join(data, "db.sqlite"), filepath.Join(fenceDir, treeFenceFile),
		filepath.Join(data, maintenance.Marker), filepath.Join(data, ".native-runtime.lock"), filepath.Join(data, ".native-maintenance-control.lock"),
		filepath.Join(data, "media/song.blob"), filepath.Join(data, "lyrics/song.lrc"), filepath.Join(data, "recordings/take.bin")} {
		info, err := os.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		pins[name] = info
	}
	if err := os.Chmod(data, 0775); err != nil {
		t.Fatal(err)
	}
	if _, err := rebind(); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("group-writable data root accepted", err)
	}
	if err := os.Chmod(data, 0755); err != nil {
		t.Fatal(err)
	}
	before = recoverySQLiteFiles(t, data)
	tampered := report.Manifest
	tampered.Bytes++
	if _, err := RebindVerifiedRetainedMasterTreeState(ctx, gate, report.SHA256, tampered, data, secrets, "db.sqlite", node); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("altered verified manifest accepted", err)
	}
	assertRecoverySQLiteFilesUnchanged(t, data, before)
	checkIntent(false)
	if already, err := rebind(); err != nil || already {
		t.Fatal("retained state rebind", already, err)
	}
	checkIntent(true)
	before = recoverySQLiteFiles(t, data)
	if _, err := RebindVerifiedRetainedMasterTreeState(ctx, gate, strings.Repeat("0", 64), report.Manifest, data, secrets, "db.sqlite", node); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("different archive matched durable intent", err)
	}
	assertRecoverySQLiteFilesUnchanged(t, data, before)
	if already, err := rebind(); err != nil || !already {
		t.Fatal("retained state rebind retry", already, err)
	}
	for path, before := range pins {
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, after) {
			t.Fatal("retained file inode changed", path, err)
		}
	}
	for _, name := range []string{"media/song.blob", "lyrics/song.lrc", "recordings/take.bin"} {
		raw, err := os.ReadFile(filepath.Join(data, name))
		if err != nil || string(raw) != name {
			t.Fatal("retained business file changed", name, err)
		}
	}
	if enabled, err := gate.Enabled(); err != nil || !enabled {
		t.Fatal("retained restore lost maintenance", enabled, err)
	}

	db, err := recoverySQLite(filepath.Join(data, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := OpenSQLiteWithMaster(ctx, db, master)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := os.OpenRoot(fenceDir)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Close()
	if _, err := OpenFence(ctx, store, fence, fenceDir); err != nil {
		t.Fatal("open retained fence", err)
	}
	lease, err := store.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if name, err := store.ResolveDirectoryForRecoveryWithLease(ctx, lease, directoryID); err != nil || name != "album" {
		t.Fatal("read retained archive state", name, err)
	}
}
