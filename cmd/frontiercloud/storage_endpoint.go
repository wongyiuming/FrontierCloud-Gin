package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

type storageEndpointWriter interface {
	MoveStorageEndpoint(context.Context, string, string, string) error
	RebindStorageEndpoint(context.Context, string, store.Relationship, string) error
}

func storageEndpointCommand(name string, arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	id := flags.String("confirm-node-id", "", "exact local identity to preserve")
	previous := flags.String("previous-endpoint", "", "exact stored old storage endpoint")
	next := flags.String("endpoint", "", "new explicit high-port HTTPS storage endpoint")
	relationship := flags.String("relationship", "", "Master's active downstream relationship; required for storage-rebind")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	canonical, err := node.Endpoint(*next)
	if err != nil || canonical != *next || !node.ValidIdentifier(*id) || *previous == "" || flags.NArg() != 0 {
		return errors.New("invalid offline storage handover arguments")
	}
	if name == "storage-rebind" && !node.ValidIdentifier(*relationship) {
		return errors.New("storage-rebind requires relationship")
	}
	if name == "storage-endpoint" && *relationship != "" {
		return errors.New("storage-endpoint accepts no relationship")
	}
	settings, err := config.Load()
	if err != nil {
		return err
	}
	if name == "storage-endpoint" && (settings.DeploymentMode != config.DeploymentStorage || settings.StorageEndpoint != *next) {
		return errors.New("storage-endpoint requires only_stroge configured for the new endpoint")
	}
	gate, err := maintenance.Open(settings.DataRoot)
	if err != nil {
		return err
	}
	defer gate.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = gate.Inspect(ctx, func(ctx context.Context) error {
		if err := bindStore(ctx, settings); err != nil {
			return err
		}
		var db store.Store
		if settings.DatabaseType == config.DatabaseSQLite {
			db, err = sqlitestore.OpenExisting(ctx, settings.SQLitePath)
		} else {
			db, err = openExistingStore(ctx, settings)
		}
		if err != nil {
			return err
		}
		defer db.Close()
		identity, err := node.OpenExisting(ctx, db.Nodes(), settings.SecretsDirectory)
		if err != nil {
			return err
		}
		if identity.ID != *id {
			return store.ErrNodeState
		}
		snapshot, err := db.Maintenance().InspectMaintenance(ctx)
		if err != nil {
			return err
		}
		if !snapshot.LogicalIdle {
			return store.ErrBackupBusy
		}
		writer, ok := db.Nodes().(storageEndpointWriter)
		if !ok {
			return errors.New("store does not support offline storage handover")
		}
		if name == "storage-endpoint" {
			return writer.MoveStorageEndpoint(ctx, *id, *previous, *next)
		}
		if identity.Role != "Master" {
			return store.ErrNodeState
		}
		rel, err := db.Nodes().Relationship(ctx, *relationship)
		if err != nil {
			return err
		}
		if rel.Direction != "downstream" || rel.State != "active" || (rel.Endpoint != *previous && rel.Endpoint != *next) {
			return store.ErrNodeState
		}
		transport := node.NewTransport()
		defer transport.Close()
		if _, err := transport.Identity(ctx, *next, rel.PeerID, rel.PublicKey, "Follower"); err != nil {
			return err
		}
		rel.Endpoint = *previous
		return writer.RebindStorageEndpoint(ctx, *id, rel, *next)
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(map[string]any{"endpoint": *next, "identity_preserved": true, "maintenance_enabled": true, "native_quiescent": true, "scope": "native-processes-sharing-DATA_ROOT"})
}
