package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/bootstrap"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// Admission is exact: same-generation preparation or the retained generation
// 4/5/6 to generation-7 additive migrations. This never performs reverse DDL.
func prepareReleaseCommand(arguments []string) error {
	flags := flag.NewFlagSet("prepare-release", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	generation := flags.Int("confirm-generation", 0, "exact compatible existing logical generation")
	from := flags.Int("from-generation", 0, "exact source schema; defaults to target for same-generation preparation")
	confirmation := flags.String("confirm-node-id", "", "exact existing identity for an approved generation change")
	backup := flags.String("backup-sha256", "", "operator-verified source recovery archive SHA-256")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *generation != migrations.Generation {
		return errors.New("prepare-release requires exact supported generation")
	}
	if *from == 0 {
		*from = *generation
	}
	if !supportedReleaseSource(*from) {
		return errors.New("source generation has no defined upgrade/recovery path")
	}
	if *from != *generation {
		id, e := hex.DecodeString(*confirmation)
		if e != nil || len(id) != 16 {
			return errors.New("schema change requires the exact original NodeID")
		}
		hash, e := hex.DecodeString(*backup)
		if e != nil || len(hash) != 32 {
			return errors.New("schema change requires a verified source recovery point")
		}
	}
	settings, err := config.Load()
	if err != nil {
		return err
	}
	gate, err := maintenance.Open(settings.DataRoot)
	if err != nil {
		return err
	}
	defer gate.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return gate.Inspect(ctx, func(ctx context.Context) error {
		if err := bindStore(ctx, settings); err != nil {
			return err
		}
		var db store.Store
		var err error
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
		if err != nil || *confirmation != "" && identity.ID != *confirmation {
			return errors.New("existing release identity could not be confirmed")
		}
		if err = inspectReleaseSource(ctx, db, *from); err != nil {
			return err
		}
		// Initialize validates idempotent shared migrations; it cannot create a
		// missing store here or downgrade a future generation.
		if err = db.Initialize(ctx); err != nil {
			return err
		}
		if err = inspectReleaseSource(ctx, db, *generation); err != nil {
			return err
		}
		if err = bootstrap.InitializeSecrets(settings.SecretsDirectory); err != nil {
			return err
		}
		return bootstrap.InitializeMediaContext(ctx, settings.DataRoot)
	})
}

func supportedReleaseSource(generation int) bool {
	return generation == migrations.Generation || migrations.Generation == 7 && (generation == 4 || generation == 5 || generation == 6)
}

// Prior generations have no knowledge of future tables. Read the exact source
// generation's transaction roster before running the retained additive DDL;
// never ask a current-schema inspector to silently skip absent future tables.
func inspectReleaseSource(ctx context.Context, db store.Store, expected int) error {
	if expected == migrations.Generation {
		snapshot, err := db.Maintenance().InspectMaintenance(ctx)
		if err != nil {
			return err
		}
		if !snapshot.LogicalIdle {
			return errors.New("unfinished resource transactions block release preparation")
		}
		return nil
	}
	if migrations.Generation != 7 || !supportedReleaseSource(expected) {
		return errors.New("unsupported schema transition")
	}
	provider, ok := db.(interface{ Database() *sql.DB })
	if !ok {
		return errors.New("offline source schema inspection unavailable")
	}
	tx, err := provider.Database().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var generation int
	if err = tx.QueryRowContext(ctx, "SELECT generation FROM frontiercloud_schema WHERE singleton=1").Scan(&generation); err != nil || generation != expected {
		return errors.New("source schema changed before migration")
	}
	queries := []string{
		"SELECT COUNT(*) FROM media_delete_operations WHERE state<>'rename_done'",
		"SELECT COUNT(*) FROM cluster_upload_sessions WHERE state NOT IN ('complete','cancelled')",
		"SELECT COUNT(*) FROM global_media_objects WHERE state<>'active'",
		"SELECT COUNT(*) FROM karaoke_recordings WHERE state NOT IN ('ready','deleted')",
		"SELECT COUNT(*) FROM karaoke_users WHERE status NOT IN ('active','banned','deleted')",
		"SELECT COUNT(*) FROM cluster_storage_members WHERE reserved_bytes<>0",
		"SELECT COUNT(*) FROM cluster_business_backups WHERE state NOT IN ('ready','failed')",
		"SELECT COUNT(*) FROM cluster_worker_jobs WHERE state NOT IN ('queued','complete')",
	}
	// Generation 5 introduces resource journals; generation 6 introduces their
	// peer bindings. Missing tables in a roster that requires them remain errors.
	if expected >= 5 {
		queries = append(queries,
			"SELECT COUNT(*) FROM migration_tasks WHERE state NOT IN ('completed','cancelled')",
			"SELECT COUNT(*) FROM migration_capacity WHERE reserved_bytes<>0",
			"SELECT COUNT(*) FROM migration_scopes",
			"SELECT COUNT(*) FROM migration_storage_journal WHERE state NOT IN ('published','deleted','aborted')",
		)
	}
	if expected >= 6 {
		queries = append(queries, "SELECT COUNT(*) FROM migration_peer_bindings b LEFT JOIN migration_storage_journal j ON b.task_id=j.task_id AND b.logical_id=j.logical_id WHERE j.task_id IS NULL")
	}
	for _, query := range queries {
		var count int64
		if err = tx.QueryRowContext(ctx, query).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return errors.New("source has unfinished resource transactions; forward DDL refused")
		}
	}
	return tx.Commit()
}
func updaterStatusCommand(output io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	value, err := (release.SocketAgent{}).Request(ctx, map[string]any{"action": "status"})
	if err != nil || value["ok"] != true {
		return errors.New("updater status unavailable")
	}
	status, ok := value["status"].(map[string]any)
	if !ok {
		return errors.New("invalid updater status")
	}
	return json.NewEncoder(output).Encode(status)
}
