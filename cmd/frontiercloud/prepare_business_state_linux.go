//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func prepareBusinessStateCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("prepare-business-state", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	masterID := flags.String("target-master-id", "", "existing fresh SQLite Master ID")
	mountProof := flags.String("mount-proof", "", "exact mounted data and secrets identity")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || !node.ValidIdentifier(*masterID) || output == nil {
		return errors.New("prepare-business-state requires pinned target and mount identities")
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
	gate, err := maintenance.OpenExisting(settings.DataRoot)
	if err != nil {
		return err
	}
	defer gate.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	checkTarget := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := checkAvailable(); err != nil {
			return err
		}
		if enabled, err := gate.Enabled(); err != nil || !enabled {
			return maintenance.ErrState
		}
		_, err := deployment.ReadRetainedBinding(settings)
		return err
	}
	if err := gate.InspectExistingSQLite(ctx, settings.DataRoot, settings.SQLitePath, func(held context.Context, check func() error) error {
		if err := checkTarget(); err != nil {
			return err
		}
		if err := verifyEmptyBusinessPreparationTarget(held, settings, *masterID); err != nil {
			return err
		}
		return check()
	}); err != nil {
		return err
	}
	// Each native phase takes the same maintenance and SQLite leases. The
	// foc caller keeps its deployment operation lock across all three phases.
	// On an interruption there is no success reply and maintenance stays on.
	if err := prepareSealedTree(ctx, settings, gate, *masterID, checkTarget); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(runtimefacts.BusinessPreparationReport{TargetMasterID: *masterID, Prepared: true})
}

func verifyEmptyBusinessPreparationTarget(ctx context.Context, settings config.Config, masterID string) error {
	db, err := sqlitestore.OpenReadOnly(ctx, settings.SQLitePath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.VerifyPreparedRuntime(ctx); err != nil {
		return err
	}
	identity, err := node.OpenExisting(ctx, db.Nodes(), settings.SecretsDirectory)
	if err != nil || identity.ID != masterID || identity.Role != "Master" {
		return backup.ErrBusinessStateTarget
	}
	var occupied bool
	if err := db.Database().QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM karaoke_users) OR EXISTS(SELECT 1 FROM karaoke_registration_daily) OR
		EXISTS(SELECT 1 FROM karaoke_audit_log) OR EXISTS(SELECT 1 FROM ip_security_audit_log) OR
		EXISTS(SELECT 1 FROM ip_security_summary) OR EXISTS(SELECT 1 FROM ip_auto_ban_events) OR
		EXISTS(SELECT 1 FROM ip_permanent_whitelist) OR EXISTS(SELECT 1 FROM webrtc_observation_events) OR
		EXISTS(SELECT 1 FROM webrtc_observation_summary)`).Scan(&occupied); err != nil || occupied {
		return backup.ErrBusinessStateTarget
	}
	root, err := os.OpenRoot(settings.DataRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := verifyFreshBusinessResources(ctx, db, root); err != nil {
		return err
	}
	return identity.CheckNativeRuntime(ctx, settings.DataRoot)
}
