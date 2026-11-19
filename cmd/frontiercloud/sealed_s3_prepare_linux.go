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
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

// prepareSealedS3Control creates only the fixed cross-process control files.
// It is deliberately separate from source/provider readiness and never opens
// the S3 service to requests.
func prepareSealedS3Control(ctx context.Context, settings config.Config, gate *maintenance.Gate, expectedMaster string) error {
	if ctx == nil || gate == nil || settings.DeploymentMode != config.DeploymentBusiness || settings.DatabaseType != config.DatabaseSQLite ||
		!node.ValidIdentifier(expectedMaster) || !filepath.IsAbs(settings.DataRoot) || filepath.Clean(settings.DataRoot) != settings.DataRoot {
		return store.ErrNodeState
	}
	return gate.InspectSQLite(ctx, settings.DataRoot, settings.SQLitePath, func(ctx context.Context, check func() error) (result error) {
		database, err := sqlitestore.OpenExisting(ctx, settings.SQLitePath)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, database.Close()) }()
		if err = database.VerifyPreparedRuntime(ctx); err != nil {
			return err
		}
		identity, err := node.OpenExisting(ctx, database.Nodes(), settings.SecretsDirectory)
		if err != nil || identity == nil || identity.Role != "Master" || identity.ID != expectedMaster {
			return store.ErrNodeState
		}
		owner, err := openRuntimeOwner(ctx, settings, database, identity)
		if err != nil {
			return err
		}
		if owner == nil {
			return store.ErrNodeState
		}
		defer func() { result = errors.Join(result, owner.Close()) }()
		tree, closeTree, err := openOpaqueMasterTree(ctx, database, settings)
		if err != nil {
			return err
		}
		if tree == nil || closeTree == nil {
			return store.ErrNodeState
		}
		defer func() { result = errors.Join(result, closeTree()) }()
		root, err := os.OpenRoot(settings.DataRoot)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, root.Close()) }()
		current, err := os.Lstat(settings.DataRoot)
		if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 {
			return store.ErrNodeState
		}
		opened, err := root.Stat(".")
		if err != nil || !os.SameFile(current, opened) || check() != nil {
			return store.ErrNodeState
		}
		return business.PrepareSelectedS3FileGate(root, check)
	})
}

func sealedS3PrepareCommand(args []string, output io.Writer) error {
	if len(args) != 1 || output == nil {
		return errors.New("sealed-s3-prepare requires the expected existing Master ID")
	}
	settings, err := config.Load()
	if err != nil {
		return err
	}
	info, err := os.Lstat(settings.DataRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("sealed-s3-prepare requires an existing deployment")
	}
	gate, err := maintenance.Open(settings.DataRoot)
	if err != nil {
		return err
	}
	defer gate.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = prepareSealedS3Control(ctx, settings, gate, args[0]); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Prepared bool `json:"prepared"`
	}{Prepared: true})
}
