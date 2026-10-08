package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

// Operator-only deletion uses the same journal, signed physical cleanup receipt
// and quota reconciliation as the account API. It never deletes an account.
func deleteStorageRecordingCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("delete-storage-recording", flag.ContinueOnError)
	master := flags.String("confirm-master-id", "", "exact local Master identity")
	member := flags.String("confirm-storage-id", "", "exact remote owner authorized for deletion")
	id := flags.String("recording", "", "one exact recording ID; no wildcard or bulk selection")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !node.ValidIdentifier(*master) || !node.ValidIdentifier(*member) || !node.ValidIdentifier(*id) || *master == *member {
		return errors.New("delete-storage-recording requires exact Master, remote storage and recording IDs")
	}
	settings, err := config.Load()
	if err != nil {
		return err
	}
	return guardedCommand(settings, func(parent context.Context) error {
		ctx, cancel := context.WithTimeout(parent, 90*time.Second)
		defer cancel()
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
		if identity.ID != *master || identity.Role != "Master" {
			return store.ErrNodeState
		}
		value, err := db.Recordings().Recording(ctx, *id)
		if err != nil {
			return err
		}
		if value == nil || value.MemberID != *member {
			return store.ErrRecordingMissing
		}
		root, err := os.OpenRoot(filepath.Join(settings.DataRoot, "recordings"))
		if err != nil {
			return err
		}
		defer root.Close()
		volume, err := recording.New(root, db.Recordings(), db.Nodes())
		if err != nil {
			return err
		}
		transport := node.NewTransport()
		defer transport.Close()
		control := node.NewService(db.Nodes(), identity, transport)
		manager := recording.NewManager(db.Recordings(), db.Karaoke(), db.Nodes(), db.Pool(), control, volume)
		if err := manager.Delete(ctx, value.UserID, value.ID, false, store.KaraokeAudit{UserID: value.UserID, Action: "operator-recording-delete"}); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]any{"recording_id": *id, "state": "deleted", "account_preserved": true})
	})
}

// A root operator may remove an explicitly confirmed local storage recording
// after its Master metadata was deliberately retired. Native ownership,
// physical journals and quota reconciliation still apply; no SQL row is forged.
func deleteOwnedRecordingCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("delete-owned-recording", flag.ContinueOnError)
	owner := flags.String("confirm-node-id", "", "exact local storage identity")
	relationship := flags.String("relationship", "", "exact upstream relationship")
	id := flags.String("recording", "", "one exact owned recording")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !node.ValidIdentifier(*owner) || !node.ValidIdentifier(*relationship) || !node.ValidIdentifier(*id) {
		return errors.New("exact owner, relationship and recording IDs required")
	}
	settings, err := config.Load()
	if err != nil {
		return err
	}
	return guardedCommand(settings, func(ctx context.Context) error {
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
		if identity.ID != *owner || identity.Role != "Follower" {
			return store.ErrNodeState
		}
		rel, err := db.Nodes().Relationship(ctx, *relationship)
		if err != nil {
			return err
		}
		if rel.Direction != "upstream" {
			return store.ErrNodeState
		}
		value, err := db.Recordings().Recording(ctx, *id)
		if err != nil {
			return err
		}
		if value == nil || value.MemberID != *owner {
			return store.ErrRecordingMissing
		}
		root, err := os.OpenRoot(filepath.Join(settings.DataRoot, "recordings"))
		if err != nil {
			return err
		}
		defer root.Close()
		volume, err := recording.New(root, db.Recordings(), db.Nodes())
		if err != nil {
			return err
		}
		unlock, err := volume.Lock(value.ID)
		if err != nil {
			return err
		}
		defer unlock()
		if err := volume.Delete(ctx, *relationship, value.UserID, value.ID, store.KaraokeAudit{}, store.NodeAudit{Actor: "operator-storage-retirement"}); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]any{"recording_id": *id, "state": "deleted", "ownership_preserved": true})
	})
}
