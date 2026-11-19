//go:build linux && ledger_fixture

package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/preprodimport"
)

func init() {
	fixtureMaintenanceCapture = func(t *testing.T, gate *maintenance.Gate, root, source, mediaID string, writer *sql.DB) {
		t.Helper()
		createDestination := func() *os.File {
			t.Helper()
			file, err := os.OpenFile(filepath.Join(t.TempDir(), "encrypted.snapshot"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = file.Close() })
			return file
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		dst := createDestination()
		err := preprodimport.FixtureEncryptedCaptureSQLite(ctx, gate, root, source, dst, mediaID, func() error {
			_, e := writer.ExecContext(ctx, `INSERT INTO isolated_wal_capture(value) VALUES('must be blocked')`)
			if e == nil || !strings.Contains(strings.ToLower(e.Error()), "locked") {
				return errors.New("writer bypassed capture transaction")
			}
			return nil
		})
		if err != nil {
			t.Fatal("real maintenance encrypted capture", err)
		}
		if info, err := dst.Stat(); err != nil || info.Size() == 0 {
			t.Fatal("missing encrypted capture", err)
		}
		failed := createDestination()
		err = preprodimport.FixtureEncryptedCaptureSQLite(ctx, gate, root, source, failed, mediaID, func() error { return errors.New("simulated capture interruption") })
		if err == nil {
			t.Fatal("interrupted capture unexpectedly succeeded")
		}
		if _, err = writer.ExecContext(ctx, `INSERT INTO isolated_wal_capture(value) VALUES('after interrupted capture')`); err != nil {
			t.Fatal("interrupted capture retained SQLite lock", err)
		}
	}
}
