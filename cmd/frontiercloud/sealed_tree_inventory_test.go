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
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestSealedTreeInventoryCommandUsesExistingStoreAndOnlyPrintsAggregates(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	dbPath := filepath.Join(root, "node.db")
	db, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	identity, err := node.Initialize(ctx, db.Nodes(), secrets)
	if err != nil {
		t.Fatal(err)
	}
	name := "music/私密专辑/私密曲目.mp3"
	ids, err := db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: name, Kind: "audio"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("SQLITE_PATH", dbPath)
	t.Setenv("DATA_ROOT", root)
	t.Setenv("SECRETS_DIR", secrets)
	var out bytes.Buffer
	if err = sealedTreeInventoryCommand(&out); err != nil {
		t.Fatal(err)
	}
	var report store.SealedTreeInventory
	if err = json.Unmarshal(out.Bytes(), &report); err != nil || !report.DatabaseSnapshotOnly || report.RuntimeReady || report.LocalObjectRows != 1 {
		t.Fatalf("invalid report: %+v %v", report, err)
	}
	for _, secret := range []string{name, "私密专辑", identity.ID, ids[name]} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("inventory output disclosed private metadata")
		}
	}
	after, err := os.ReadFile(dbPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read-only inventory changed authoritative database", err)
	}
	writable, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writable.Database().Exec("UPDATE node_identity SET `role`='Follower' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if err = writable.Close(); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err = sealedTreeInventoryCommand(&out); err == nil || out.Len() != 0 {
		t.Fatal("follower inventory emitted a report")
	}
}

func TestSealedTreeInventoryCommandDoesNotInitializeMissingStore(t *testing.T) {
	root := t.TempDir()
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("SQLITE_PATH", filepath.Join(root, "missing.db"))
	t.Setenv("DATA_ROOT", root)
	if err := sealedTreeInventoryCommand(&bytes.Buffer{}); err == nil {
		t.Fatal("missing database accepted")
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatal("inventory initialized missing state", err)
	}
	if err := command([]string{"sealed-tree-inventory", "unexpected"}); err == nil {
		t.Fatal("unexpected command argument accepted")
	}
}
