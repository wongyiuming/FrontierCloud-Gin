package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestPrepareReleaseExplicitGeneration6To7UsesRealPriorDDLAndKeepsIdentity(t *testing.T) {
	if migrations.Generation != 7 {
		t.Skip("explicit generation-7 migration acceptance")
	}
	if runtime.GOOS == "windows" {
		t.Skip("native secret ownership initialization requires Unix")
	}
	for _, kind := range []string{"success", "unconfirmed", "busy-source"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			data := filepath.Join(root, "data")
			secrets := filepath.Join(root, "secrets")
			database := filepath.Join(data, "node.sqlite")
			t.Setenv("DB_TYPE", "sqlite")
			t.Setenv("SQLITE_PATH", database)
			t.Setenv("DATA_ROOT", data)
			t.Setenv("SECRETS_DIR", secrets)
			db, e := sqlitestore.Open(database)
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			raw, e := os.ReadFile("../../migrations/sqlite/0006-schema.json")
			if e != nil {
				t.Fatal(e)
			}
			var prior struct {
				Generation int      `json:"generation"`
				Statements []string `json:"statements"`
			}
			if json.Unmarshal(raw, &prior) != nil || prior.Generation != 6 {
				t.Fatal("bad retained source DDL")
			}
			for _, statement := range prior.Statements {
				if _, e = db.Database().ExecContext(ctx, statement); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = db.Database().ExecContext(ctx, "INSERT INTO frontiercloud_schema(singleton,generation,created_at) VALUES(1,6,1)"); e != nil {
				t.Fatal(e)
			}
			if _, e = db.Database().ExecContext(ctx, "INSERT INTO ip_security_projection(singleton) VALUES(1)"); e != nil {
				t.Fatal(e)
			}
			identity, e := node.Initialize(ctx, db.Nodes(), secrets)
			if e != nil {
				t.Fatal(e)
			}
			gate, e := maintenance.Open(data)
			if e != nil {
				t.Fatal(e)
			}
			defer gate.Close()
			if e = gate.Enter(ctx, func(context.Context) error { return nil }); e != nil {
				t.Fatal(e)
			}
			if kind == "busy-source" {
				if _, e = db.Database().ExecContext(ctx, "INSERT INTO cluster_business_backups(master_id,generation,checksum,size_bytes,chunk_count,state,created_at,updated_at) VALUES(?,1,'',0,0,'receiving',1,1)", identity.ID); e != nil {
					t.Fatal(e)
				}
			}
			confirmation := identity.ID
			if kind == "unconfirmed" {
				confirmation = strings.Repeat("f", 32)
			}
			e = prepareReleaseCommand([]string{"--confirm-generation", "7", "--from-generation", "6", "--confirm-node-id", confirmation, "--backup-sha256", strings.Repeat("a", 64)})
			var generation int
			if err := db.Database().QueryRowContext(ctx, "SELECT generation FROM frontiercloud_schema WHERE singleton=1").Scan(&generation); err != nil {
				t.Fatal(err)
			}
			if kind == "success" {
				if e != nil || generation != 7 {
					t.Fatal("forward migration failed", generation, e)
				}
			} else {
				if e == nil || generation != 6 {
					t.Fatal("unsafe transition changed schema", generation, e)
				}
			}
			after, e := node.OpenExisting(ctx, db.Nodes(), secrets)
			if e != nil || after.ID != identity.ID || after.PrivateKey != identity.PrivateKey {
				t.Fatal("original identity changed", e)
			}
			if enabled, e := gate.Enabled(); e != nil || !enabled {
				t.Fatal("schema preparation opened public runtime", e)
			}
		})
	}
}
