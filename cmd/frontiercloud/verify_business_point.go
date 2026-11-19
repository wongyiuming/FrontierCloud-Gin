package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/checkpoint"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// Verification extracts only into a new private directory. It does not replace
// live state, initialize keys, promote a peer or start background workers.
func verifyBusinessPointCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("verify-business-point", flag.ContinueOnError)
	file := flags.String("file", "", "encrypted recovery point")
	checksum := flags.String("sha256", "", "independently retained SHA-256")
	generation := flags.Int64("generation", 0, "exact recovery point generation")
	target := flags.String("target", "", "new private extraction directory on the existing Master")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *file == "" || len(*checksum) != 64 || *generation <= 0 || *target == "" {
		return errors.New("verify-business-point requires file, sha256, generation and target")
	}
	c, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	db, err := openExistingStore(ctx, c)
	if err != nil {
		return err
	}
	defer db.Close()
	id, err := node.OpenExisting(ctx, db.Nodes(), c.SecretsDirectory)
	if err != nil {
		return err
	}
	sqlStore, ok := db.(interface{ Database() *sql.DB })
	if !ok || id.Role != "Master" || c.DatabaseType != config.DatabaseSQLite {
		return errors.New("verification requires the existing SQLite Master and its keys")
	}
	tree, closeTree, err := sealedtree.OpenMasterSQLite(ctx, sqlStore.Database(), c.DataRoot, c.SecretsDirectory, id.ID)
	if err != nil {
		return err
	}
	defer closeTree()
	v, err := vault.OpenExisting(c.SecretsDirectory)
	if err != nil {
		return err
	}
	named, err := os.Lstat(*file)
	if err != nil || !named.Mode().IsRegular() {
		return checkpoint.ErrCheckpoint
	}
	in, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil || !os.SameFile(named, opened) {
		return checkpoint.ErrCheckpoint
	}
	header, err := checkpoint.Restore(ctx, in, *checksum, opened.Size(), v, id.ID, *generation, *target, func(ctx context.Context, db *sql.DB) error {
		if err := tree.ValidateCheckpointDatabase(ctx, db); err != nil {
			return err
		}
		return tree.ValidateCheckpointLyrics(ctx, db, filepath.Join(*target, "media"), id.ID)
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(map[string]any{"verified": true, "master_id": id.ID, "generation": header.Generation, "schema_generation": header.Schema, "extracted_to": *target, "live_state_replaced": false, "requires_retained_master_keys_and_media": true})
}
