//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestSQLiteBackupLeaseAllowsRealOperatorStatus(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	dbPath := filepath.Join(root, "node.db")
	db, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	identity, err := node.Initialize(ctx, db.Nodes(), secrets)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dbPath, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("SQLITE_PATH", dbPath)
	t.Setenv("DATA_ROOT", root)
	t.Setenv("SECRETS_DIR", secrets)
	gate, err := maintenance.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	limited, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = gate.InspectSQLite(limited, root, dbPath, func(c context.Context, check func() error) error {
		done := make(chan error, 1)
		go func() {
			var out bytes.Buffer
			e := operatorStatusCommand(&out)
			if e == nil {
				var fact runtimefacts.RuntimeFact
				e = json.Unmarshal(out.Bytes(), &fact)
				if e == nil && (fact.NodeID != identity.ID || !fact.NativeMaintenance) {
					e = maintenance.ErrState
				}
			}
			done <- e
		}()
		select {
		case e := <-done:
			if e != nil {
				return e
			}
			return check()
		case <-c.Done():
			return c.Err()
		}
	})
	if err != nil {
		t.Fatal("operator status under same database lease", err)
	}
}
