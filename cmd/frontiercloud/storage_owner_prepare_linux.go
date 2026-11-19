//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// storageOwnerPrepareCommand never creates an identity or imports old data.
// The operator first enters native maintenance and supplies the existing ID.
func storageOwnerPrepareCommand(args []string, out io.Writer) error {
	if len(args) != 1 || out == nil {
		return errors.New("storage-owner-prepare requires the existing Follower ID")
	}
	c, err := config.Load()
	if err != nil {
		return err
	}
	if info, e := os.Lstat(c.DataRoot); e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("storage-owner-prepare requires an existing deployment")
	}
	gate, err := maintenance.Open(c.DataRoot)
	if err != nil {
		return err
	}
	defer gate.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = prepareEmptyStorageOwner(ctx, c, gate, args[0]); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]bool{"prepared": true})
}

func prepareEmptyStorageOwner(ctx context.Context, c config.Config, gate *maintenance.Gate, expected string) error {
	return prepareEmptyOwner(ctx, c, gate, expected, "Follower")
}

// prepareEmptyOwner is shared by Master and Follower; callers must order it
// before tree activation, while the same offline maintenance gate is held.
func prepareEmptyOwner(ctx context.Context, c config.Config, gate *maintenance.Gate, expected, role string) error {
	validMode := role == "Follower" && c.DeploymentMode == config.DeploymentStorage || role == "Master" && c.DeploymentMode == config.DeploymentBusiness
	if ctx == nil || gate == nil || !validMode || c.DatabaseType != config.DatabaseSQLite || !node.ValidIdentifier(expected) || !filepath.IsAbs(c.DataRoot) || filepath.Clean(c.DataRoot) != c.DataRoot {
		return store.ErrNodeState
	}
	return gate.InspectSQLite(ctx, c.DataRoot, c.SQLitePath, func(ctx context.Context, check func() error) error {
		db, err := sqlitestore.OpenExisting(ctx, c.SQLitePath)
		if err != nil {
			return err
		}
		defer db.Close()
		identity, err := node.OpenExisting(ctx, db.Nodes(), c.SecretsDirectory)
		if err != nil || identity.ID != expected || identity.Role != role {
			return store.ErrNodeState
		}
		var generation, markers int
		if db.Database().QueryRowContext(ctx, `SELECT generation FROM frontiercloud_schema WHERE singleton=1`).Scan(&generation) != nil || generation != migrations.Generation || db.Database().QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_owner_fence`).Scan(&markers) != nil || markers > 1 {
			return store.ErrNodeState
		}
		data, err := os.OpenRoot(c.DataRoot)
		if err != nil {
			return err
		}
		defer data.Close()
		mediaInfo, err := data.Lstat("media")
		if err != nil || !mediaInfo.IsDir() {
			return store.ErrNodeState
		}
		recordingsInfo, err := data.Lstat("recordings")
		if err != nil || !recordingsInfo.IsDir() {
			return store.ErrNodeState
		}
		mediaPath := filepath.Join(c.DataRoot, "media")
		root, err := os.OpenRoot(mediaPath)
		if err != nil {
			return err
		}
		defer root.Close()
		opened, err := root.Stat(".")
		if err != nil || !os.SameFile(mediaInfo, opened) {
			return store.ErrNodeState
		}
		var fence *ownerfence.Fence
		if markers == 0 {
			snapshot, err := db.Maintenance().InspectMaintenance(ctx)
			if err != nil || !snapshot.LogicalIdle {
				return store.ErrNodeState
			}
			for _, query := range []string{
				`SELECT EXISTS(SELECT 1 FROM media_objects WHERE NOT (object_kind='lyric' AND media_path='lyrics/default.lrc'))`,
				`SELECT EXISTS(SELECT 1 FROM global_media_objects WHERE state<>'deleted')`,
				`SELECT EXISTS(SELECT 1 FROM karaoke_recordings WHERE state<>'deleted')`,
				`SELECT EXISTS(SELECT 1 FROM s3_objects WHERE state<>'deleted')`,
			} {
				var exists bool
				if db.Database().QueryRowContext(ctx, query).Scan(&exists) != nil || exists {
					return store.ErrNodeState
				}
			}
			if sealedtree.CheckEmptyStorageDestination(data) != nil || check() != nil {
				return store.ErrNodeState
			}
			if err = root.Mkdir(".opaque-aliases", 0700); err != nil {
				return store.ErrNodeState
			}
			dir, e := root.Open(".")
			if e != nil {
				return e
			}
			e = errors.Join(dir.Sync(), dir.Close())
			if e != nil {
				return e
			}
			fence, err = ownerfence.Create(root, mediaPath, identity)
		} else {
			fence, err = ownerfence.Open(root, mediaPath, identity)
		}
		if err != nil || fence == nil || check() != nil {
			return store.ErrNodeState
		}
		repo, ok := db.Nodes().(interface {
			ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
			InitializeOwnerControlMarker(context.Context) error
			AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
		})
		if !ok || repo.ConfigureOwnerControlFence(func(ctx context.Context, exclusive bool) (store.OwnerControlLease, error) {
			return fence.Acquire(ctx, exclusive)
		}) != nil {
			return store.ErrNodeState
		}
		if markers == 0 {
			if err = repo.InitializeOwnerControlMarker(ctx); err != nil {
				return err
			}
		}
		lease, err := repo.AcquireOwnerControlShared(ctx)
		if err != nil || lease == nil {
			return store.ErrNodeState
		}
		defer lease.Release()
		if lease.Check(ctx) != nil || check() != nil {
			return store.ErrNodeState
		}
		return nil
	})
}
