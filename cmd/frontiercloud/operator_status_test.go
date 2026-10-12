package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestOperatorStatusDoesNotInitializeMissingDatabase(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing.db")
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("SQLITE_PATH", missing)
	t.Setenv("DATA_ROOT", root)
	if e := operatorStatusCommand(&bytes.Buffer{}); e == nil {
		t.Fatal("absent store accepted")
	}
	entries, e := os.ReadDir(root)
	if e != nil || len(entries) != 0 {
		t.Fatal("read-only status created state", entries, e)
	}
}
func TestOperatorStatusPreservesIdentityAndReportsOfflineFenceWithoutNewLocks(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	path := filepath.Join(root, "node.db")
	db, e := sqlite.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	identity, e := node.Initialize(ctx, db.Nodes(), secrets)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("SQLITE_PATH", path)
	t.Setenv("DATA_ROOT", root)
	t.Setenv("SECRETS_DIR", secrets)
	if e = os.WriteFile(filepath.Join(root, ".frontiercloud-native-maintenance"), []byte("frontiercloud-native-maintenance-v1\n"), 0600); e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if e = operatorStatusCommand(&out); e != nil {
		t.Fatal(e)
	}
	var fact operator.RuntimeFact
	if e = json.Unmarshal(out.Bytes(), &fact); e != nil || fact.NodeID != identity.ID || fact.Role != "Standalone" || fact.Database.SchemaGeneration != 4 || !fact.NativeMaintenance || !fact.Maintenance {
		t.Fatal(fact, e)
	}
	for _, name := range []string{".site-control.lock", ".native-maintenance-control.lock", ".native-runtime.lock"} {
		if _, e := os.Stat(filepath.Join(root, name)); !os.IsNotExist(e) {
			t.Fatal("created a lifecycle lock", name, e)
		}
	}
	for _, secret := range []string{"private_key", "credential", "admin_key", "premaster", "endpoint", "summary"} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("unallowlisted runtime detail", secret)
		}
	}
}
