//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func importBusinessStateCommand(arguments []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("import-business-state", flag.ContinueOnError)
	generation := flags.Int64("generation", 0, "exact v2 source backup generation")
	checksum := flags.String("sha256", "", "independently recorded source SHA-256")
	size := flags.Int64("bytes", 0, "exact source artifact length")
	masterID := flags.String("target-master-id", "", "existing fresh SQLite Master ID")
	mountProof := flags.String("mount-proof", "", "exact mounted data and secrets identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *generation <= 0 || len(*checksum) != 64 || *size <= 0 || *size > backup.MaxBusinessStateBytes || !node.ValidIdentifier(*masterID) {
		return errors.New("import-business-state requires pinned source, target and mount identities")
	}
	settings, err := config.Load()
	if err != nil {
		return err
	}
	checkAvailable, err := businessStateTargetGuard(settings, *mountProof)
	if err != nil {
		return err
	}
	if err := checkAvailable(); err != nil {
		return err
	}
	if _, err := deployment.ReadRetainedBinding(settings); err != nil {
		return err
	}
	gate, err := maintenance.OpenExisting(settings.DataRoot)
	if err != nil {
		return err
	}
	defer gate.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	var report backup.BusinessStateReport
	err = gate.InspectExistingSQLite(ctx, settings.DataRoot, settings.SQLitePath, func(ctx context.Context, check func() error) error {
		if err := checkAvailable(); err != nil {
			return err
		}
		db, err := sqlitestore.OpenExisting(ctx, settings.SQLitePath)
		if err != nil {
			return err
		}
		defer db.Close()
		if err := db.VerifyPreparedRuntime(ctx); err != nil {
			return err
		}
		identity, err := node.OpenExisting(ctx, db.Nodes(), settings.SecretsDirectory)
		if err != nil || identity.ID != *masterID || identity.Role != "Master" {
			return backup.ErrBusinessStateTarget
		}
		owner, err := openRuntimeOwner(ctx, settings, db, identity)
		if err != nil || owner == nil {
			return backup.ErrBusinessStateTarget
		}
		defer owner.Close()
		if err := sealedtree.VerifyMasterSQLite(ctx, db.Database(), settings.DataRoot, settings.SecretsDirectory, identity.ID); err != nil {
			return err
		}
		snapshot, err := db.Maintenance().InspectMaintenance(ctx)
		if err != nil {
			return err
		}
		for name, count := range snapshot.Pending {
			// A prepared empty tree already has a root and an owner fence.
			// ImportBusinessState separately checks for placements and uploads.
			if name != "sealed_tree_unrecoverable" && count != 0 {
				return backup.ErrBusinessStateTarget
			}
		}
		fence := func() error {
			if err := check(); err != nil {
				return err
			}
			if err := checkAvailable(); err != nil {
				return err
			}
			_, err := deployment.ReadRetainedBinding(settings)
			return err
		}
		report, err = backup.ImportBusinessState(ctx, input, backup.Expectation{Generation: *generation, Checksum: *checksum, Bytes: *size}, db.Database(), identity.ID, fence)
		return err
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(report)
}
