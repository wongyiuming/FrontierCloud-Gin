//go:build linux && ledger_fixture

package sealedtree

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// FixtureTreeCaptureMaster constructs only synthetic files in test-owned empty
// directories. It is never compiled into a normal product build.
func FixtureTreeCaptureMaster(ctx context.Context, data, secrets string) (string, error) {
	keys, err := os.OpenRoot(secrets)
	if err != nil {
		return "", err
	}
	defer keys.Close()
	master, err := CreateTreeSecretFile(keys)
	if err != nil {
		return "", err
	}
	defer clear(master)
	v, err := vault.Open(secrets)
	if err != nil {
		return "", err
	}
	sealed, err := v.Seal(protocol.Encode(bytes.Repeat([]byte{4}, 32)))
	if err != nil {
		return "", err
	}
	dbPath := filepath.Join(data, "db.sqlite")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		return "", err
	}
	defer db.Close()
	tree, err := New(master, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		return "", err
	}
	store, err := InitializeSQLite(ctx, db, tree, strings.Repeat("a", 64))
	if err != nil {
		return "", err
	}
	if err = os.Chmod(dbPath, 0600); err != nil {
		return "", err
	}
	nodeID := strings.Repeat("b", 32)
	statements, err := migrations.Statements("sqlite")
	if err != nil {
		return "", err
	}
	for _, statement := range statements {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			return "", err
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO frontiercloud_schema VALUES(1,?,123)`, migrations.Generation); err != nil {
		return "", err
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO node_identity VALUES(1,?,'Master','https://master.test',?,123)`, nodeID, sealed); err != nil {
		return "", err
	}
	fenceDir := filepath.Join(data, MasterFenceDirectory)
	if err = os.Mkdir(fenceDir, 0700); err != nil {
		return "", err
	}
	fence, err := os.OpenRoot(fenceDir)
	if err != nil {
		return "", err
	}
	defer fence.Close()
	if _, err = InitializeFence(ctx, store, fence, fenceDir); err != nil {
		return "", err
	}
	entry := Entry{ParentID: store.rootID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "album"}
	if err = store.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
		return "", err
	}
	binding := existingMasterBinding(tree, store.rootID, nodeID, sealed, 123)
	defer clear(binding)
	if err = os.WriteFile(filepath.Join(fenceDir, existingMasterBindingFile), binding, 0600); err != nil {
		return "", err
	}
	gate, err := maintenance.Open(data)
	if err != nil {
		return "", err
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		return "", err
	}
	return nodeID, nil
}
