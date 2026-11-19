package main

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestOpaqueMasterTreeLayoutRefusesPartialRestore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	settings := config.Config{DataRoot: dir, SecretsDirectory: filepath.Join(dir, "secrets"), DatabaseType: config.DatabaseSQLite, DeploymentMode: config.DeploymentBusiness}
	check := func() error { return checkOpaqueMasterTreeLayout(ctx, db, settings) }
	if err := check(); err != nil {
		t.Fatal("ordinary fresh startup refused", err)
	}
	for _, directory := range []string{settings.SecretsDirectory, filepath.Join(dir, sealedtree.MasterFenceDirectory)} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(settings.SecretsDirectory, sealedtree.MasterKeyFile)
	key := bytes.Repeat([]byte{1}, 32)
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("restored tree artifacts with no database root accepted")
	}
	codec, err := sealedtree.New(key, bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	source, err := sql.Open("sqlite", filepath.Join(dir, "source.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := sealedtree.InitializeSQLite(ctx, source, codec, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	// Restore only the real database root record to reproduce a partial restore.
	var verifier, rootEncryptionID string
	var salt, root []byte
	if err := source.QueryRowContext(ctx, `SELECT verifier,salt,root_encryption_id,root_sealed FROM sealed_tree_meta WHERE singleton=1`).Scan(&verifier, &salt, &rootEncryptionID, &root); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Database().ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, verifier, salt, rootEncryptionID, root); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("existing database root with missing fence and binding accepted")
	}
	for _, file := range sealedtree.MasterStatePaths() {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(file)), key, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := check(); err == nil {
		t.Fatal("tree with no original Master identity accepted")
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("database with missing original tree key accepted")
	}
	if _, err := os.Lstat(keyPath); !os.IsNotExist(err) {
		t.Fatal("startup inspection replaced a missing tree key", err)
	}
	var identities int
	if err := db.Database().QueryRowContext(ctx, `SELECT COUNT(*) FROM node_identity`).Scan(&identities); err != nil || identities != 0 {
		t.Fatal("startup inspection created an identity", identities, err)
	}
}

func TestOpaqueRegistryRequiresOriginalIdentityAndVault(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	mediaRoot, secrets := filepath.Join(dir, "media"), filepath.Join(dir, "secrets")
	if err := os.MkdirAll(filepath.Join(mediaRoot, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkOpaqueRegistryIdentity(ctx, db.Nodes(), mediaRoot, secrets); err == nil {
		t.Fatal("registry with missing identity and vault accepted")
	}
	if _, err := os.Stat(filepath.Join(secrets, "node-vault.key")); !os.IsNotExist(err) {
		t.Fatal("guard created a new key", err)
	}
	if _, err := node.Initialize(ctx, db.Nodes(), secrets); err != nil {
		t.Fatal(err)
	}
	if err := checkOpaqueRegistryIdentity(ctx, db.Nodes(), mediaRoot, secrets); err != nil {
		t.Fatal("existing identity and vault rejected", err)
	}
	if err := os.Remove(filepath.Join(secrets, "node-vault.key")); err != nil {
		t.Fatal(err)
	}
	if err := checkOpaqueRegistryIdentity(ctx, db.Nodes(), mediaRoot, secrets); err == nil {
		t.Fatal("registry with lost vault accepted")
	}
	if _, err := node.Initialize(ctx, db.Nodes(), secrets); err == nil {
		t.Fatal("identity regenerated missing vault")
	}
	if _, err := os.Stat(filepath.Join(secrets, "node-vault.key")); !os.IsNotExist(err) {
		t.Fatal("lost key was recreated", err)
	}
}
