package maintenance

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	_ "modernc.org/sqlite"
)

// sqliteWritersStopped is intentionally not constructible through a production
// API. A future lifecycle controller must establish that all writers, including
// old and unmanaged binaries, have stopped and cannot restart. SQLite's busy
// result and this package's cooperative runtime lease alone do not prove that.
type sqliteWritersStopped struct {
	gate  *Gate
	check func() error
	used  atomic.Bool
}

// checkpointSQLite is an unregistered maintenance primitive, not a source
// capture or a production command. Failure leaves the maintenance marker set.
// SQLite itself owns recovery and sidecar removal; this never removes files.
func (g *Gate) checkpointSQLite(ctx context.Context, dataRoot, databasePath string, stopped *sqliteWritersStopped) error {
	if g == nil || ctx == nil || stopped == nil || stopped.gate != g || stopped.check == nil || !stopped.used.CompareAndSwap(false, true) {
		return ErrState
	}
	return g.InspectSQLite(ctx, dataRoot, databasePath, func(ctx context.Context, checkLease func() error) error {
		check := func() error {
			if ctx.Err() != nil || checkLease() != nil || stopped.check() != nil {
				return ErrState
			}
			return nil
		}
		if err := check(); err != nil {
			return err
		}
		// A rollback journal could represent an incomplete transaction. Until
		// recovery provenance is supported, refuse it without opening SQLite.
		if _, err := os.Lstat(databasePath + "-journal"); !errors.Is(err, os.ErrNotExist) {
			return ErrState
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
		u.RawQuery = url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(100)"}}.Encode()
		db, err := sql.Open("sqlite", u.String())
		if err != nil {
			return err
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		run := func() error {
			conn, err := db.Conn(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err = check(); err != nil {
				return err
			}
			var mode string
			if err = conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || (mode != "wal" && mode != "delete") {
				return ErrState
			}
			if mode == "wal" {
				var busy, frames, done int
				if err = conn.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &frames, &done); err != nil || busy != 0 || frames != 0 || done != 0 {
					return ErrState
				}
			}
			if err = check(); err != nil {
				return err
			}
			if err = conn.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&mode); err != nil || mode != "delete" {
				return ErrState
			}
			rows, err := conn.QueryContext(ctx, "PRAGMA integrity_check")
			if err != nil {
				return err
			}
			defer rows.Close()
			if !rows.Next() {
				return ErrState
			}
			var result string
			if err = rows.Scan(&result); err != nil || result != "ok" || rows.Next() || rows.Err() != nil {
				return ErrState
			}
			return check()
		}
		runErr := run()
		closeErr := db.Close()
		if err = errors.Join(runErr, closeErr); err != nil {
			return err
		}
		if err = check(); err != nil {
			return err
		}
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			if _, err = os.Lstat(databasePath + suffix); !errors.Is(err, os.ErrNotExist) {
				return ErrState
			}
		}
		file, err := os.Open(absolute)
		if err != nil {
			return err
		}
		defer file.Close()
		var header [20]byte
		if _, err = file.ReadAt(header[:], 0); err != nil || string(header[:16]) != "SQLite format 3\x00" || header[18] != 1 || header[19] != 1 {
			return ErrState
		}
		return check()
	})
}
