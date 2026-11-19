//go:build linux

package operator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestTreeRetainedInstallPreservesUnselectedAndRepairsSQLite(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	data, keys := filepath.Join(base, "data"), filepath.Join(base, "keys")
	for _, name := range []string{data, keys, filepath.Join(data, sealedtree.MasterFenceDirectory), filepath.Join(data, "media")} {
		if err := os.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(name, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	database := filepath.Join(data, "db.sqlite")
	write(database, "archive-database")
	for _, name := range sealedtree.MasterStatePaths() {
		write(filepath.Join(data, name), "archived-"+name)
	}
	write(filepath.Join(keys, "tree-master.key"), strings.Repeat("x", 32))
	write(filepath.Join(keys, "node-vault.key"), strings.Repeat("v", 32))
	write(filepath.Join(data, "media", "untouched"), "business")
	gate, err := maintenance.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(base, "source.tar")
	m := recovery.Manifest{NodeID: strings.Repeat("a", 32), Role: "Master", Revision: strings.Repeat("b", 40), Database: "sqlite", Scope: recovery.UpgradeStateScope, Consistency: "native-offline-and-deployment-writers-stopped", KeyReferences: []string{"runtime_secrets/tree-master.key", "runtime_secrets/node-vault.key"}}
	selection := append([]string{"db.sqlite"}, sealedtree.MasterStatePaths()...)
	report, err := recovery.CreateTreeArchive(ctx, gate, data, database, archive, m, []recovery.Root{{Class: "data", Directory: data, IncludePaths: selection}, {Class: "runtime_secrets", Directory: keys}}, func(_ context.Context, check func() error) (func(recovery.Manifest) (json.RawMessage, error), func() error, error) {
		return fixtureTreeEvidence, check, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	material := filepath.Join(base, "material")
	if _, err = recovery.ApplyTreeStateArchive(ctx, archive, material, report.SHA256, m.NodeID); err != nil {
		t.Fatal(err)
	}
	write(database, "failed-database")
	write(filepath.Join(keys, "extra-secret"), "failed-secret")
	fence := filepath.Join(data, sealedtree.MasterStatePaths()[0])
	oldFence, err := os.Stat(fence)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Services: map[string]Service{"web": {Environment: map[string]string{"DATA_ROOT": "/app/data", "SQLITE_PATH": "/app/data/db.sqlite"}, Volumes: []Mount{{Type: "bind", Source: data, Target: "/app/data"}}}}}
	p, err := prepareTreeRetainedInstall(ctx, cfg, Receipt{Role: "master", Database: "sqlite"}, map[string]string{"data": data, "runtime_secrets": keys}, report)
	if err != nil {
		t.Fatal(err)
	}
	failed := filepath.Join(base, "failed")
	// testing.TempDir's numbered child is created with 0777 subject to umask;
	// the retained snapshot parent must instead be explicitly private.
	if err = os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	if err = p.retain(ctx, failed); !errors.Is(err, recovery.ErrUnsafe) {
		t.Fatalf("non-private retained parent accepted: %v", err)
	}
	if _, err = os.Lstat(failed); !os.IsNotExist(err) {
		t.Fatalf("unsafe parent published retained state: %v", err)
	}
	if err = os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	if err = p.retain(ctx, failed); err != nil {
		t.Fatal(err)
	}
	if err = p.retain(ctx, failed); err != nil {
		t.Fatal(err)
	}
	if err = p.install(ctx, material); err != nil {
		t.Fatal(err)
	}
	currentFence, err := os.Stat(fence)
	if err != nil || !os.SameFile(oldFence, currentFence) {
		t.Fatal("unchanged tree fence inode replaced", err)
	}
	if got, _ := os.ReadFile(database); string(got) != "archive-database" {
		t.Fatalf("database: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(data, "media", "untouched")); string(got) != "business" {
		t.Fatalf("business data changed: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(failed, "data", "db.sqlite")); string(got) != "failed-database" {
		t.Fatalf("failed state not retained: %q", got)
	}
	if _, err = os.Lstat(filepath.Join(keys, "extra-secret")); !os.IsNotExist(err) {
		t.Fatalf("extra state not removed: %v", err)
	}
	if err = p.install(ctx, material); err != nil {
		t.Fatalf("idempotent install: %v", err)
	}
	write(database, "interrupted-db")
	write(filepath.Join(keys, "node-vault.key"), "bad-key")
	if err = p.repairSQLite(ctx, material); err == nil {
		t.Fatal("repair admitted altered non-SQLite state")
	}
	write(filepath.Join(keys, "node-vault.key"), strings.Repeat("v", 32))
	if err = p.repairSQLite(ctx, material); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(database); string(got) != "archive-database" {
		t.Fatalf("repaired database: %q", got)
	}
}
