//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestExistingBusinessTreeInitializationRequiresOfflineBinding(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fenceDir := filepath.Join(dir, "tree-private")
	if err := os.Mkdir(fenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(dir, "business.sqlite")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(databasePath)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = schema.Initialize(ctx, db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(databasePath, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TABLE legacy_business_fixture(value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO legacy_business_fixture VALUES('preserve')`); err != nil {
		t.Fatal(err)
	}
	c := config.Config{DataRoot: dir, SQLitePath: databasePath, DatabaseType: config.DatabaseSQLite, SecretsDirectory: filepath.Join(dir, "secrets")}
	gate, err := maintenance.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	tree := fixture(t)
	root := strings.Repeat("a", 64)
	if err = InitializeExistingSQLiteOffline(ctx, c, gate, tree, root, fenceDir); !errors.Is(err, ErrLegacyWritersUnfenced) {
		t.Fatal("unfenced product initializer did not remain closed", err)
	}
	run := func() error { return initializeExistingSQLiteOffline(ctx, c, gate, tree, root, fenceDir) }
	if err = run(); err == nil {
		t.Fatal("initialized without maintenance")
	}
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("initialized without deployment binding")
	}
	if err = deployment.Bind(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("initialized without existing node vault")
	}
	nodeVault, err := vault.Open(c.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("initialized without existing Master identity")
	}
	sealedKey, err := nodeVault.Seal(protocol.Encode(bytes.Repeat([]byte{5}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO node_identity(singleton,node_id,`role`,endpoint,private_key,created_at) VALUES(1,?,'Master','',?,123)", strings.Repeat("f", 32), sealedKey); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "UPDATE node_identity SET `role`='Follower' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("Follower identity accepted")
	}
	if _, err = db.ExecContext(ctx, "UPDATE node_identity SET `role`='Master' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO cluster_storage_members(member_id,relationship_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at) VALUES(?,NULL,'MasterLocal','Local',1,100,0,1,100,'online',1,1)`, strings.Repeat("f", 32)); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("outstanding durable reservation accepted")
	}
	if _, err = db.ExecContext(ctx, `UPDATE cluster_storage_members SET reserved_bytes=0 WHERE member_id=?`, strings.Repeat("f", 32)); err != nil {
		t.Fatal(err)
	}
	partialFence := filepath.Join(fenceDir, treeFenceFile)
	if err = os.WriteFile(partialFence, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("partial fence accepted")
	}
	var count int
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_meta`).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial fence modified tree metadata", err)
	}
	if err = os.Remove(partialFence); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO sealed_tree_operation_ids(operation_id) VALUES(?)`, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("partial tree accepted")
	}
	if _, err = db.ExecContext(ctx, `DELETE FROM sealed_tree_operation_ids WHERE operation_id=?`, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE frontiercloud_schema SET generation=9 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("wrong generation accepted")
	}
	if _, err = db.ExecContext(ctx, `UPDATE frontiercloud_schema SET generation=12 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE frontiercloud_schema_migrations SET checksum='invalid' WHERE generation=12`); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("invalid generation 12 journal accepted")
	}
	if _, err = db.ExecContext(ctx, `UPDATE frontiercloud_schema_migrations SET checksum=? WHERE generation=12`, migrations.SelectedUploadIntentChecksum); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO selected_upload_cancellations(operation_id,object_index,blob_index,cancellation_mac) VALUES(?,?,?,?)`, strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64)); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("unresolved selected cancellation accepted")
	}
	if _, err = db.ExecContext(ctx, `DELETE FROM selected_upload_cancellations`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TRIGGER fail_tree_root BEFORE INSERT ON sealed_tree_meta BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("root write fault accepted")
	}
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids`).Scan(&count); err != nil || count != 0 {
		t.Fatal("root failure did not roll back reservation", err)
	}
	if _, err = os.Lstat(partialFence); !os.IsNotExist(err) {
		t.Fatal("root failure created fence", err)
	}
	if _, err = db.ExecContext(ctx, `DROP TRIGGER fail_tree_root`); err != nil {
		t.Fatal(err)
	}
	if err = run(); err != nil {
		t.Fatal("initialization", err)
	}
	if err = run(); err != nil {
		t.Fatal("idempotent reopen", err)
	}
	wrong, err := New(bytes.Repeat([]byte{0x43}, 32), bytes.Repeat([]byte{0x91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = initializeExistingSQLiteOffline(ctx, c, gate, wrong, root, fenceDir); err == nil {
		t.Fatal("wrong tree key accepted")
	}
	if _, err = db.ExecContext(ctx, "UPDATE node_identity SET node_id=? WHERE singleton=1", strings.Repeat("e", 32)); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("replaced Master identity accepted")
	}
	if _, err = db.ExecContext(ctx, "UPDATE node_identity SET node_id=? WHERE singleton=1", strings.Repeat("f", 32)); err != nil {
		t.Fatal(err)
	}
	bindingPath := filepath.Join(dir, deployment.Binding)
	binding, err := os.ReadFile(bindingPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(bindingPath, []byte("invalid binding"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("altered deployment binding accepted")
	}
	if err = os.WriteFile(bindingPath, binding, 0600); err != nil {
		t.Fatal(err)
	}
	var value string
	if err = db.QueryRowContext(ctx, `SELECT value FROM legacy_business_fixture`).Scan(&value); err != nil || value != "preserve" {
		t.Fatal("legacy data changed", err)
	}
	if _, err = os.Lstat(partialFence); err != nil {
		t.Fatal("missing initialized fence", err)
	}
	if err = os.Remove(partialFence); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("missing existing fence silently recreated")
	}
	if _, err = os.Lstat(partialFence); !os.IsNotExist(err) {
		t.Fatal("damaged fence was recreated", err)
	}
	if enabled, e := gate.Enabled(); e != nil || !enabled {
		t.Fatal("maintenance unexpectedly reopened", e)
	}
	c.DatabaseType = config.DatabaseMySQL
	if err = run(); err == nil {
		t.Fatal("MySQL tree runtime accepted")
	}
}

func TestMaintenanceSQLiteDetectsPathReplacement(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "business.sqlite")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(path, path+".hardlink"); err != nil {
		t.Fatal(err)
	}
	called := false
	if err = gate.InspectSQLite(ctx, dir, path, func(context.Context, func() error) error { called = true; return nil }); err == nil || called {
		t.Fatal("hard-linked database admitted")
	}
	if err = os.Remove(path + ".hardlink"); err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(dir, "real")
	if err = os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(realDir, "db"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "linked")
	if err = os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	called = false
	if err = gate.InspectSQLite(ctx, dir, filepath.Join(linkDir, "db"), func(context.Context, func() error) error { called = true; return nil }); err == nil || called {
		t.Fatal("database under symlinked component admitted")
	}
	err = gate.InspectSQLite(ctx, dir, path, func(_ context.Context, recheck func() error) error {
		if e := os.Rename(path, path+".held"); e != nil {
			return e
		}
		if e := os.WriteFile(path, []byte("replacement"), 0600); e != nil {
			return e
		}
		if recheck() == nil {
			t.Error("replaced database inode accepted")
		}
		return nil
	})
	if err == nil {
		t.Fatal("replacement succeeded")
	}
	if enabled, e := gate.Enabled(); e != nil || !enabled {
		t.Fatal("replacement opened maintenance", e)
	}
	markerPath := filepath.Join(dir, maintenance.Marker)
	marker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	err = gate.InspectSQLite(ctx, dir, path, func(_ context.Context, recheck func() error) error {
		if e := os.Rename(markerPath, markerPath+".held"); e != nil {
			return e
		}
		if e := os.WriteFile(markerPath, marker, 0600); e != nil {
			return e
		}
		if recheck() == nil {
			t.Error("replaced maintenance marker accepted")
		}
		return nil
	})
	if err == nil {
		t.Fatal("maintenance marker replacement succeeded")
	}
	for _, name := range []string{".native-runtime.lock", ".native-maintenance-control.lock"} {
		err = gate.InspectSQLite(ctx, dir, path, func(_ context.Context, recheck func() error) error {
			lock := filepath.Join(dir, name)
			if e := os.Rename(lock, lock+".held"); e != nil {
				return e
			}
			if e := os.WriteFile(lock, nil, 0600); e != nil {
				return e
			}
			if recheck() == nil {
				t.Error("replaced maintenance lock accepted", name)
			}
			return nil
		})
		if err == nil {
			t.Fatal("maintenance lock replacement succeeded", name)
		}
	}
}
