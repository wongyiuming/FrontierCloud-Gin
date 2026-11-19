package maintenance

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteSnapshotReader limits a caller to query operations on the same
// transaction. SQLite query_only additionally rejects writes on that connection.
// Callers must not attempt to change connection pragmas or retain returned rows.
type SQLiteSnapshotReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// InspectSQLiteImmediate executes a bounded offline read under the existing
// persistent maintenance marker and an IMMEDIATE SQLite transaction. It reads
// committed WAL pages through SQLite and blocks competing SQLite writers while
// the callback runs. The callback must respect ctx, close all rows, and perform
// any source authentication before returning. A result is a snapshot only: no
// ownership, publication, crash-recovery intent or post-return consistency is
// implied. This primitive has no command or product endpoint.
func (g *Gate) InspectSQLiteImmediate(ctx context.Context, dataRoot, databasePath string, read func(context.Context, SQLiteSnapshotReader, func() error) error) error {
	if g == nil || ctx == nil || read == nil {
		return ErrState
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second {
		return ErrState
	}
	return g.InspectSQLite(ctx, dataRoot, databasePath, func(ctx context.Context, check func() error) error {
		if err := check(); err != nil {
			return err
		}
		absolute, err := filepath.Abs(databasePath)
		if err != nil {
			return err
		}
		uriPath := filepath.ToSlash(absolute)
		if !strings.HasPrefix(uriPath, "/") {
			uriPath = "/" + uriPath
		}
		u := url.URL{Scheme: "file", Path: uriPath}
		u.RawQuery = url.Values{"mode": {"rw"}, "_txlock": {"immediate"}, "_pragma": {"busy_timeout(100)"}}.Encode()
		db, err := sql.Open("sqlite", u.String())
		if err != nil {
			return err
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		run := func() (result error) {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer func() {
				if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
					result = errors.Join(result, rollbackErr)
				}
			}()
			if _, err = tx.ExecContext(ctx, "PRAGMA query_only=ON"); err != nil {
				return err
			}
			var queryOnly int
			if err = tx.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil || queryOnly != 1 || check() != nil {
				return ErrState
			}
			if err = read(ctx, tx, check); err != nil {
				return err
			}
			if err = tx.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil || queryOnly != 1 || check() != nil {
				return ErrState
			}
			return tx.Rollback()
		}
		runErr := run()
		closeErr := db.Close()
		if err = errors.Join(runErr, closeErr); err != nil {
			return err
		}
		return check()
	})
}
