package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func initializeRuntimeSchema(ctx context.Context, database store.Store, settings config.Config) error {
	artifact := filepath.Join(settings.SecretsDirectory, sealedtree.MasterKeyFile)
	if settings.DeploymentMode == config.DeploymentStorage {
		artifact = filepath.Join(settings.DataRoot, "media", ".opaque-aliases", ".owner-control-binding")
	}
	if _, err := os.Lstat(artifact); errors.Is(err, os.ErrNotExist) {
		return database.Initialize(ctx)
	} else if err != nil {
		return err
	}
	prepared, ok := database.(interface{ VerifyPreparedRuntime(context.Context) error })
	if !ok || settings.DatabaseType != config.DatabaseSQLite {
		return store.ErrNodeState
	}
	return prepared.VerifyPreparedRuntime(ctx)
}

func openRuntimeIdentity(ctx context.Context, database store.Store, settings config.Config) (*node.Identity, error) {
	prepared, err := runtimeOwnerPresent(ctx, database, settings.DataRoot)
	if err != nil {
		return nil, err
	}
	if !prepared {
		return node.Initialize(ctx, database.Nodes(), settings.SecretsDirectory)
	}
	if settings.DatabaseType != config.DatabaseSQLite {
		return nil, store.ErrNodeState
	}
	identity, err := node.OpenExisting(ctx, database.Nodes(), settings.SecretsDirectory)
	if err != nil {
		return nil, err
	}
	if settings.DeploymentMode == config.DeploymentStorage && identity.Role != "Follower" || settings.DeploymentMode == config.DeploymentBusiness && identity.Role != "Master" {
		return nil, store.ErrNodeState
	}
	return identity, nil
}

func runtimeOwnerPresent(ctx context.Context, database store.Store, dataRoot string) (bool, error) {
	sqlStore, ok := database.(interface{ Database() *sql.DB })
	if !ok || sqlStore.Database() == nil {
		return false, store.ErrNodeState
	}
	var markers int
	if err := sqlStore.Database().QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_owner_fence`).Scan(&markers); err != nil {
		return false, err
	}
	base := filepath.Join(dataRoot, "media", ".opaque-aliases")
	binding, bindingErr := os.Lstat(filepath.Join(base, ".owner-control-binding"))
	lock, lockErr := os.Lstat(filepath.Join(base, ".owner-control-lock"))
	if markers == 0 && errors.Is(bindingErr, os.ErrNotExist) && errors.Is(lockErr, os.ErrNotExist) {
		return false, nil
	}
	if markers != 1 || bindingErr != nil || lockErr != nil || !binding.Mode().IsRegular() || !lock.Mode().IsRegular() {
		return false, store.ErrNodeState
	}
	return true, nil
}

// Check for a partially restored tree before initializing a node or starting
// legacy media recovery. Authenticated state alone does not establish that
// encrypted data is ready to serve.
func checkOpaqueMasterTreeLayout(ctx context.Context, database store.Store, settings config.Config) error {
	_, closeTree, err := openOpaqueMasterTree(ctx, database, settings)
	if err != nil || closeTree == nil {
		return err
	}
	return closeTree()
}

func openOpaqueMasterTree(ctx context.Context, database store.Store, settings config.Config) (*sealedtree.SQLStore, func() error, error) {
	if ctx == nil || database == nil || settings.DataRoot == "" || settings.SecretsDirectory == "" {
		return nil, nil, store.ErrNodeState
	}
	sqlStore, ok := database.(interface{ Database() *sql.DB })
	if !ok || sqlStore.Database() == nil {
		return nil, nil, store.ErrNodeState
	}
	var roots int
	if err := sqlStore.Database().QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_meta`).Scan(&roots); err != nil {
		return nil, nil, err
	}
	key, keyErr := os.Lstat(filepath.Join(settings.SecretsDirectory, sealedtree.MasterKeyFile))
	fence, fenceErr := os.Lstat(filepath.Join(settings.DataRoot, sealedtree.MasterFenceDirectory))
	if roots == 0 && errors.Is(keyErr, os.ErrNotExist) && errors.Is(fenceErr, os.ErrNotExist) {
		return nil, nil, nil
	}
	if roots != 1 || keyErr != nil || fenceErr != nil || !key.Mode().IsRegular() || key.Size() != 32 || !fence.IsDir() || settings.DatabaseType != config.DatabaseSQLite || settings.DeploymentMode == config.DeploymentStorage {
		return nil, nil, errors.New("encrypted tree database, key and fence directory must be restored together on the original SQLite Master")
	}
	for _, name := range sealedtree.MasterStatePaths() {
		state, err := os.Lstat(filepath.Join(settings.DataRoot, filepath.FromSlash(name)))
		if err != nil || !state.Mode().IsRegular() || state.Size() != 32 {
			return nil, nil, errors.New("encrypted tree fence and Master binding must be restored with the database")
		}
	}
	identity, err := database.Nodes().ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID == "" || identity.PrivateKey == "" {
		return nil, nil, errors.New("encrypted tree requires the existing Master identity")
	}
	tree, closeTree, err := sealedtree.OpenMasterSQLite(ctx, sqlStore.Database(), settings.DataRoot, settings.SecretsDirectory, identity.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypted tree does not authenticate to the existing Master: %w", err)
	}
	keyBytes, err := tree.CapacityKey()
	if err != nil {
		return nil, nil, errors.Join(err, closeTree())
	}
	defer clear(keyBytes)
	capacity, ok := database.Pool().(interface {
		VerifyOpaqueCapacityKey(context.Context, []byte) error
	})
	if !ok {
		return nil, nil, errors.Join(store.ErrNodeState, closeTree())
	}
	if err := capacity.VerifyOpaqueCapacityKey(ctx, keyBytes); err != nil {
		return nil, nil, errors.Join(err, closeTree())
	}
	return tree, closeTree, nil
}

// An existing owner registry requires the original durable identity and vault.
// In particular, restoring an empty database must not silently create a fresh
// key or node identity while encrypted owner records already exist.
func checkOpaqueRegistryIdentity(ctx context.Context, repo store.NodeRepository, mediaRoot, secrets string) error {
	if repo == nil || ctx == nil || mediaRoot == "" || secrets == "" {
		return store.ErrNodeState
	}
	registry := filepath.Join(mediaRoot, ".opaque-aliases")
	info, err := os.Lstat(registry)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return store.ErrNodeState
	}
	identity, err := repo.ReadIdentity(ctx)
	if err != nil || identity.ID == "" || identity.PrivateKey == "" {
		return store.ErrNodeState
	}
	key, err := os.Lstat(filepath.Join(secrets, "node-vault.key"))
	if err != nil || !key.Mode().IsRegular() || key.Mode()&os.ModeSymlink != 0 {
		return store.ErrNodeState
	}
	again, err := os.Lstat(registry)
	if err != nil || !again.IsDir() || again.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, again) {
		return store.ErrNodeState
	}
	return nil
}
