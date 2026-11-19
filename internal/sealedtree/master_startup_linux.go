//go:build linux

package sealedtree

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func VerifyMasterSQLite(ctx context.Context, db *sql.DB, dataRoot, secretsDir, masterID string) error {
	_, closeTree, err := OpenMasterSQLite(ctx, db, dataRoot, secretsDir, masterID)
	if err != nil {
		return err
	}
	return closeTree()
}

// OpenMasterSQLite authenticates the retained namespace without creating any
// files. The caller holds the native runtime lease and must close the handle
// after all dependent tree operations have finished.
func OpenMasterSQLite(ctx context.Context, db *sql.DB, dataRoot, secretsDir, masterID string) (_ *SQLStore, closeTree func() error, err error) {
	if ctx == nil || db == nil || !lowerHex(masterID, 32) || !filepath.IsAbs(dataRoot) || filepath.Clean(dataRoot) != dataRoot || !filepath.IsAbs(secretsDir) || filepath.Clean(secretsDir) != secretsDir {
		return nil, nil, ErrInvalid
	}
	keys, err := openPrivateTreeDirectory(secretsDir)
	if err != nil {
		return nil, nil, err
	}
	defer keys.Close()
	secret, err := OpenTreeSecretFile(keys)
	if err != nil {
		return nil, nil, err
	}
	defer clear(secret)
	_, rawVault, err := readPrivateTreeVault(keys)
	if err != nil {
		return nil, nil, err
	}
	nodeVault, err := vault.New(string(rawVault))
	clear(rawVault)
	if err != nil {
		return nil, nil, err
	}
	tree, err := OpenSQLiteWithMaster(ctx, db, secret)
	if err != nil {
		return nil, nil, err
	}
	fenceDir := filepath.Join(dataRoot, MasterFenceDirectory)
	fenceRoot, err := openPrivateTreeDirectory(fenceDir)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if closeTree == nil {
			fenceRoot.Close()
		}
	}()
	if err = recoveryFenceLocation(dataRoot, fenceRoot, fenceDir); err != nil {
		return nil, nil, err
	}
	if _, err = OpenFence(ctx, tree, fenceRoot, fenceDir); err != nil {
		return nil, nil, err
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer lease.Release()
	if _, err = recoveryMasterBinding(ctx, db, tree, fenceRoot, nodeVault, masterID); err != nil {
		return nil, nil, err
	}
	named, err := os.Lstat(secretsDir)
	opened, rootErr := keys.Stat(".")
	if err != nil || rootErr != nil || !named.IsDir() || !os.SameFile(named, opened) {
		return nil, nil, ErrFenceChanged
	}
	if err = lease.Check(ctx); err != nil {
		return nil, nil, err
	}
	return tree, fenceRoot.Close, nil
}
