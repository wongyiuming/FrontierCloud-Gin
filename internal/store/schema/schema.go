// Package schema initializes and upgrades the shared authoritative database schema.
package schema

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

var tablePattern = regexp.MustCompile("(?i)^CREATE TABLE(?: IF NOT EXISTS)?\\s+`?(\\w+)")

// Preserve existing lock names where valid. Legal longer database names need
// a bounded hash suffix because MySQL advisory lock names allow 64 characters.
const mysqlMigrationLockName = "CASE WHEN CHAR_LENGTH(CONCAT('frontiercloud:schema-migrations:', DATABASE()))<=64 THEN CONCAT('frontiercloud:schema-migrations:', DATABASE()) ELSE CONCAT('frontiercloud:schema-migrations:', LEFT(SHA2(DATABASE(),256),32)) END"

// Initialize reserves one connection for the migration lock and its statements.
func Initialize(ctx context.Context, database *sql.DB, backend string) error {
	statements, err := migrations.Statements(backend)
	if err != nil {
		return err
	}
	conn, err := database.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if backend == "sqlite" {
		if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			return err
		}
	} else {
		var acquired int
		if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK("+mysqlMigrationLockName+", 60)").Scan(&acquired); err != nil {
			return err
		}
		if acquired != 1 {
			return fmt.Errorf("schema migration lock timed out")
		}
		defer func() {
			release, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = conn.ExecContext(release, "SELECT RELEASE_LOCK("+mysqlMigrationLockName+")")
		}()
		if _, err := conn.ExecContext(ctx, "START TRANSACTION"); err != nil {
			return err
		}
	}
	defer func() {
		rollback, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(rollback, "ROLLBACK")
	}()
	tables, err := tableNames(ctx, conn, backend)
	if err != nil {
		return err
	}
	if len(tables) == 0 {
		for _, statement := range statements {
			if _, err := conn.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("initialize schema: %w", err)
			}
		}
		// MySQL DDL commits implicitly. Keep bootstrap singleton rows atomic.
		if backend == "mysql" {
			if _, err := conn.ExecContext(ctx, "START TRANSACTION"); err != nil {
				return err
			}
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO ip_security_projection(singleton) VALUES (1)"); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO frontiercloud_schema(singleton, generation, created_at) VALUES (1, ?, ?)", migrations.Generation, time.Now().Unix()); err != nil {
			return err
		}
	} else {
		if !tables["frontiercloud_schema"] {
			return fmt.Errorf("existing database has no schema marker; automatic adoption is unsupported")
		}
		var generation int
		if err := conn.QueryRowContext(ctx, "SELECT generation FROM frontiercloud_schema WHERE singleton=1").Scan(&generation); err != nil {
			return fmt.Errorf("read schema generation: %w", err)
		}
		if generation > migrations.Generation {
			return fmt.Errorf("database generation %d is newer than runtime generation %d; downgrade refused", generation, migrations.Generation)
		}
		if generation == 1 {
			for _, statement := range statements {
				if match := tablePattern.FindStringSubmatch(statement); len(match) == 2 && match[1] == "frontiercloud_schema_migrations" {
					if _, err := conn.ExecContext(ctx, statement); err != nil {
						return err
					}
				}
			}
			if backend == "mysql" {
				if _, err := conn.ExecContext(ctx, "START TRANSACTION"); err != nil {
					return err
				}
			}
			if _, err := conn.ExecContext(ctx, "DELETE FROM frontiercloud_schema_migrations WHERE generation=2"); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "INSERT INTO frontiercloud_schema_migrations(generation, migration_name, checksum, applied_at) VALUES (2, ?, ?, ?)", migrations.JournalName, migrations.JournalChecksum, time.Now().Unix()); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "UPDATE frontiercloud_schema SET generation=2 WHERE singleton=1"); err != nil {
				return err
			}
			generation = 2
		}
		if generation == 2 {
			for _, statement := range statements {
				if match := tablePattern.FindStringSubmatch(statement); len(match) == 2 && (match[1] == "media_encryption" || match[1] == "media_crypto_keys") {
					if _, err := conn.ExecContext(ctx, statement); err != nil {
						return err
					}
				}
			}
			if backend == "mysql" {
				if _, err := conn.ExecContext(ctx, "START TRANSACTION"); err != nil {
					return err
				}
			}
			if _, err := conn.ExecContext(ctx, "DELETE FROM frontiercloud_schema_migrations WHERE generation=3"); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES (3,?,?,?)", migrations.EncryptionName, migrations.EncryptionChecksum, time.Now().Unix()); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "UPDATE frontiercloud_schema SET generation=3 WHERE singleton=1"); err != nil {
				return err
			}
			generation = 3
		}
		if generation == 3 {
			if err := widenPriority(ctx, conn, backend, statements); err != nil {
				return fmt.Errorf("migrate priority range: %w", err)
			}
			if backend == "mysql" {
				if _, err := conn.ExecContext(ctx, "START TRANSACTION"); err != nil {
					return err
				}
			}
			if _, err := conn.ExecContext(ctx, "DELETE FROM frontiercloud_schema_migrations WHERE generation=4"); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES (4,?,?,?)", migrations.PriorityName, migrations.PriorityChecksum, time.Now().Unix()); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "UPDATE frontiercloud_schema SET generation=4 WHERE singleton=1"); err != nil {
				return err
			}
			generation = 4
		}
		if generation == 4 {
			// Additive DDL is replayable after a MySQL crash: CREATE IF NOT
			// EXISTS completes before the atomic journal/generation update.
			for _, statement := range statements {
				match := tablePattern.FindStringSubmatch(statement)
				if len(match) == 2 && strings.HasPrefix(match[1], "migration_") && match[1] != "migration_peer_bindings" && !strings.HasPrefix(match[1], "migration_plan_") || strings.HasPrefix(statement, "CREATE INDEX IF NOT EXISTS idx_migration_") && !strings.HasPrefix(statement, "CREATE INDEX IF NOT EXISTS idx_migration_plan_") {
					if _, err := conn.ExecContext(ctx, statement); err != nil {
						return fmt.Errorf("migrate resource task journal: %w", err)
					}
				}
			}
			if backend == "mysql" {
				if _, err := conn.ExecContext(ctx, "START TRANSACTION"); err != nil {
					return err
				}
			}
			if _, err := conn.ExecContext(ctx, "DELETE FROM frontiercloud_schema_migrations WHERE generation=5"); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES (5,?,?,?)", migrations.ResourceMigrationName, migrations.ResourceMigrationChecksum, time.Now().Unix()); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "UPDATE frontiercloud_schema SET generation=5 WHERE singleton=1"); err != nil {
				return err
			}
			generation = 5
		}
		if generation == 5 {
			for _, statement := range statements {
				match := tablePattern.FindStringSubmatch(statement)
				if len(match) == 2 && match[1] == "migration_peer_bindings" {
					if _, err := conn.ExecContext(ctx, statement); err != nil {
						return fmt.Errorf("migrate peer resource bindings: %w", err)
					}
				}
			}
			if backend == "mysql" {
				if _, err := conn.ExecContext(ctx, "START TRANSACTION"); err != nil {
					return err
				}
			}
			if _, err := conn.ExecContext(ctx, "DELETE FROM frontiercloud_schema_migrations WHERE generation=6"); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES (6,?,?,?)", migrations.PeerBindingsName, migrations.PeerBindingsChecksum, time.Now().Unix()); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "UPDATE frontiercloud_schema SET generation=6 WHERE singleton=1"); err != nil {
				return err
			}
			generation = 6
		}
		if generation == 6 {
			for _, statement := range statements {
				match := tablePattern.FindStringSubmatch(statement)
				if len(match) == 2 && strings.HasPrefix(match[1], "migration_plan_") || strings.HasPrefix(statement, "CREATE INDEX IF NOT EXISTS idx_migration_plan_") {
					if _, err := conn.ExecContext(ctx, statement); err != nil {
						return fmt.Errorf("migrate paged resource plans: %w", err)
					}
				}
			}
			if backend == "mysql" {
				if _, err := conn.ExecContext(ctx, "START TRANSACTION"); err != nil {
					return err
				}
			}
			if _, err := conn.ExecContext(ctx, "DELETE FROM frontiercloud_schema_migrations WHERE generation=7"); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES (7,?,?,?)", migrations.MigrationPlansName, migrations.MigrationPlansChecksum, time.Now().Unix()); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "UPDATE frontiercloud_schema SET generation=7 WHERE singleton=1"); err != nil {
				return err
			}
			generation = 7
		}
		if generation != migrations.Generation {
			return fmt.Errorf("unsupported schema generation %d", generation)
		}
	}
	tables, err = tableNames(ctx, conn, backend)
	if err != nil {
		return err
	}
	for _, statement := range statements {
		match := tablePattern.FindStringSubmatch(statement)
		if len(match) == 2 && !tables[match[1]] {
			return fmt.Errorf("incomplete schema: missing table %s", match[1])
		}
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	return err
}

func tableNames(ctx context.Context, conn *sql.Conn, backend string) (map[string]bool, error) {
	query := "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
	if backend == "mysql" {
		query = "SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema=DATABASE() AND TABLE_TYPE='BASE TABLE'"
	}
	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names[strings.TrimSpace(name)] = true
	}
	return names, rows.Err()
}
