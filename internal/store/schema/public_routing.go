package schema

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func checkPublicRoutingJournal(ctx context.Context, conn *sql.Conn, required bool) error {
	var name, checksum string
	err := conn.QueryRowContext(ctx, "SELECT migration_name,checksum FROM frontiercloud_schema_migrations WHERE generation=9").Scan(&name, &checksum)
	if errors.Is(err, sql.ErrNoRows) && !required {
		return nil
	}
	if err != nil {
		return fmt.Errorf("public routing schema journal is missing or unreadable: %w", err)
	}
	if name != migrations.PublicRoutingName || checksum != migrations.PublicRoutingChecksum {
		return errors.New("public routing schema journal identity mismatch")
	}
	return nil
}

func writePublicRoutingJournal(ctx context.Context, conn *sql.Conn) error {
	if err := checkPublicRoutingJournal(ctx, conn, false); err != nil {
		return err
	}
	var count int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM frontiercloud_schema_migrations WHERE generation=9").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		_, err := conn.ExecContext(ctx, "INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES (9,?,?,?)", migrations.PublicRoutingName, migrations.PublicRoutingChecksum, time.Now().Unix())
		return err
	}
	return nil
}

// Like the S3 migration, MySQL's additive DDL can survive an interrupted
// transaction. Accept only the complete canonical shape before journaling it.
func preparePublicRoutingSchema(ctx context.Context, conn *sql.Conn, backend string, statements []string, create bool) error {
	definitions := map[string]string{}
	for _, statement := range statements {
		match := tablePattern.FindStringSubmatch(statement)
		if len(match) != 2 || (match[1] != "public_ingress_config" && match[1] != "native_transport_policy") {
			continue
		}
		definitions[match[1]] = statement
		if create {
			if _, err := conn.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
	}
	if len(definitions) != 2 {
		return errors.New("incomplete canonical public routing table definitions")
	}
	for table, statement := range definitions {
		if err := checkS3Columns(ctx, conn, backend, table, statement); err != nil {
			return err
		}
		if err := checkS3Constraints(ctx, conn, backend, table, statement); err != nil {
			return err
		}
	}
	return nil
}
