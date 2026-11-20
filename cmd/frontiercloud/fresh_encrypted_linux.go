//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func prepareFreshEncryptedRuntime(ctx context.Context, settings config.Config, gate *maintenance.Gate) error {
	if settings.DatabaseType != config.DatabaseSQLite {
		return errors.New("fresh encrypted deployment requires SQLite")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return gate.SerializeBootstrap(ctx, func(ctx context.Context) error {
		if _, err := os.Lstat(settings.SQLitePath); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if enabled, err := gate.Enabled(); err != nil || enabled {
			return maintenance.ErrState
		}
		for _, path := range []string{
			settings.SQLitePath + "-wal", settings.SQLitePath + "-shm", settings.SQLitePath + "-journal",
			filepath.Join(settings.DataRoot, deployment.Binding),
			filepath.Join(settings.DataRoot, sealedtree.MasterFenceDirectory),
			filepath.Join(settings.SecretsDirectory, "node-vault.key"),
			filepath.Join(settings.SecretsDirectory, sealedtree.MasterKeyFile),
		} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return errors.New("database missing from an existing deployment")
			}
		}
		local := store.NodePromotion{Role: "Follower", Endpoint: settings.StorageEndpoint}
		if settings.DeploymentMode == config.DeploymentBusiness {
			origin, err := node.MasterEndpoint(settings.AdminOrigin)
			if err != nil {
				return err
			}
			local.Role, local.Endpoint, local.Allocation = "Master", origin, store.GiB
		}
		var id string
		if err := gate.Enter(ctx, func(ctx context.Context) error {
			root, err := os.OpenRoot(settings.DataRoot)
			if err != nil {
				return err
			}
			defer root.Close()
			if err = sealedtree.CheckEmptyStorageDestination(root); err != nil {
				return err
			}
			_, local.PhysicalFree, err = fsutil.DiskUsage(root)
			if err != nil {
				return err
			}
			db, err := openRuntimeStore(ctx, settings)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := db.Initialize(ctx); err != nil {
				return err
			}
			identity, err := node.Initialize(ctx, db.Nodes(), settings.SecretsDirectory)
			if err != nil {
				return err
			}
			if err = identity.RecordNativeRuntime(ctx, settings.DataRoot); err != nil {
				return err
			}
			row, err := db.Nodes().PromoteIdentity(ctx, local, store.NodeAudit{Actor: "fresh-deployment"})
			id = row.ID
			return err
		}); err != nil {
			return err
		}
		if local.Role == "Master" {
			if err := prepareSealedTree(ctx, settings, gate, id, ctx.Err); err != nil {
				return err
			}
		} else if err := prepareEmptyStorageOwner(ctx, settings, gate, id); err != nil {
			return err
		}
		return gate.Resume(ctx, func(context.Context) error { return nil })
	})
}
