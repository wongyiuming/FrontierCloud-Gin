package main

import (
	"database/sql"
	"errors"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/checkpoint"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func configureBusinessCheckpoint(settings config.Config, database store.Store, tree *sealedtree.SQLStore, builder *backup.Builder, master string) error {
	if tree == nil {
		return nil
	}
	sqlStore, ok := database.(interface{ Database() *sql.DB })
	if !ok || settings.DatabaseType != config.DatabaseSQLite {
		return errors.New("sealed recovery points require SQLite")
	}
	private, err := vault.OpenExisting(settings.SecretsDirectory)
	if err != nil {
		return err
	}
	source := &checkpoint.Source{DB: sqlStore.Database(), Tree: tree, Vault: private, MediaRoot: filepath.Join(settings.DataRoot, "media"), Scratch: filepath.Join(settings.DataRoot, ".business-backups"), MasterID: master}
	builder.ConfigureCheckpoint(source.Write)
	return nil
}
