package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This explicit local operator command reads an existing database only. Its
// counts do not authorize migration, prove cross-node consistency or enable
// an encrypted tree. No path, raw ID, media bytes or key is printed.
func sealedTreeInventoryCommand(output io.Writer) error {
	if output == nil {
		return errors.New("sealed tree inventory output required")
	}
	settings, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	db, err := openExistingStore(ctx, settings)
	if err != nil {
		return err
	}
	defer db.Close()
	identity, err := node.OpenExisting(ctx, db.Nodes(), settings.SecretsDirectory)
	if err != nil || identity == nil || (identity.Role != "Master" && identity.Role != "Standalone") {
		return errors.New("existing authoritative Master identity required")
	}
	return sealedTreeInventoryFromStore(ctx, db, output)
}

func sealedTreeInventoryFromStore(ctx context.Context, db store.Store, output io.Writer) error {
	if ctx == nil || db == nil || output == nil {
		return errors.New("sealed tree inventory unavailable")
	}
	repo, ok := db.Media().(store.SealedTreeInventoryRepository)
	if !ok {
		return errors.New("sealed tree inventory unsupported")
	}
	report, err := repo.SealedTreeInventory(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(report)
}
