package schema

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func checkLegacyReadIntentJournal(ctx context.Context, conn *sql.Conn, required bool) error {
	var name, checksum string
	err := conn.QueryRowContext(ctx, `SELECT migration_name,checksum FROM frontiercloud_schema_migrations WHERE generation=11`).Scan(&name, &checksum)
	if errors.Is(err, sql.ErrNoRows) && !required {
		return nil
	}
	if err != nil || name != migrations.LegacyReadIntentName || checksum != migrations.LegacyReadIntentChecksum {
		return errors.New("legacy read intent migration journal mismatch")
	}
	return nil
}

func writeLegacyReadIntentJournal(ctx context.Context, conn *sql.Conn) error {
	if err := checkLegacyReadIntentJournal(ctx, conn, false); err != nil {
		return err
	}
	var n int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM frontiercloud_schema_migrations WHERE generation=11`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		_, err := conn.ExecContext(ctx, `INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES(11,?,?,?)`, migrations.LegacyReadIntentName, migrations.LegacyReadIntentChecksum, time.Now().Unix())
		return err
	}
	return nil
}

// DDL may survive a MySQL interruption; accept only the canonical empty
// schema before journaling it. Active intent recovery is not installed yet.
func prepareLegacyReadIntent(ctx context.Context, conn *sql.Conn, backend string, create, requireEmpty bool) error {
	sqlite, e := migrations.LegacyReadIntentStatements("sqlite")
	if e != nil {
		return e
	}
	mysql, e := migrations.LegacyReadIntentStatements("mysql")
	if e != nil {
		return e
	}
	sum := sha256.Sum256([]byte("sqlite\n" + strings.Join(sqlite, "\n") + "\nmysql\n" + strings.Join(mysql, "\n")))
	if hex.EncodeToString(sum[:]) != migrations.LegacyReadIntentChecksum {
		return errors.New("legacy read intent checksum mismatch")
	}
	statements := sqlite
	if backend == "mysql" {
		statements = mysql
	} else if backend != "sqlite" {
		return errors.New("unsupported database")
	}
	if len(statements) == 0 {
		return errors.New("missing legacy read intent schema")
	}
	if create {
		if _, e = conn.ExecContext(ctx, statements[0]); e != nil {
			return e
		}
	}
	const table = "legacy_read_control_intents"
	if e = checkS3Columns(ctx, conn, backend, table, statements[0]); e != nil {
		return e
	}
	if e = checkS3Constraints(ctx, conn, backend, table, statements[0]); e != nil {
		return e
	}
	if e = checkSealedTreeCollations(ctx, conn, backend, table); e != nil {
		return e
	}
	primary := s3Index{name: "PRIMARY", table: table, columns: []string{"operation_index"}, unique: true}
	if backend == "sqlite" {
		primary.name = "sqlite_autoindex_" + table + "_1"
	}
	cols, unique, e := s3IndexColumns(ctx, conn, backend, table, primary.name)
	if e != nil || !unique || strings.Join(cols, ",") != "operation_index" {
		return errors.New("invalid legacy read intent primary key")
	}
	if e = checkSealedIndexOrdering(ctx, conn, backend, primary); e != nil {
		return e
	}
	for _, index := range []s3Index{
		{name: "uq_legacy_read_control_challenge", table: table, columns: []string{"challenge_tag"}, unique: true},
		{name: "uq_legacy_read_control_nonce", table: table, columns: []string{"nonce"}, unique: true},
	} {
		if create {
			if e = ensureS3Index(ctx, conn, backend, index); e != nil {
				return e
			}
		}
		cols, unique, e = s3IndexColumns(ctx, conn, backend, table, index.name)
		if e != nil || !unique || strings.Join(cols, ",") != strings.Join(index.columns, ",") {
			return errors.New("invalid legacy read intent unique index")
		}
		if e = checkSealedIndexOrdering(ctx, conn, backend, index); e != nil {
			return e
		}
	}
	if requireEmpty {
		var n int64
		if e = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); e != nil || n != 0 {
			return fmt.Errorf("legacy read intents require offline recovery")
		}
	}
	return nil
}
