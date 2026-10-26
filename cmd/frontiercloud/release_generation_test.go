package main

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestPrepareReleaseExplicitPriorGenerationsUseRealDDLAndKeepIdentity(t *testing.T) {
	if migrations.Generation != 7 && migrations.Generation != 8 {
		t.Skip("explicit generation-7 and generation-8 migration acceptance")
	}
	if runtime.GOOS == "windows" {
		t.Skip("native secret ownership initialization requires Unix")
	}
	sources := []int{4, 5, 6}
	if migrations.Generation == 8 {
		sources = append(sources, 7)
	}
	for _, sourceGeneration := range sources {
		for _, kind := range []string{"success", "unconfirmed", "busy-source"} {
			t.Run(fmt.Sprintf("%d-%s", sourceGeneration, kind), func(t *testing.T) {
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
				raw, e := os.ReadFile(fmt.Sprintf("../../migrations/sqlite/%04d-schema.json", sourceGeneration))
				if e != nil {
					t.Fatal(e)
				}
				var prior struct {
					Generation int      `json:"generation"`
					Statements []string `json:"statements"`
				}
				if json.Unmarshal(raw, &prior) != nil || prior.Generation != sourceGeneration {
					t.Fatal("bad retained source DDL")
				}
				for _, statement := range prior.Statements {
					if _, e = db.Database().ExecContext(ctx, statement); e != nil {
						t.Fatal(e)
					}
				}
				if _, e = db.Database().ExecContext(ctx, "INSERT INTO frontiercloud_schema(singleton,generation,created_at) VALUES(1,?,1)", sourceGeneration); e != nil {
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
				e = prepareReleaseCommand([]string{"--confirm-generation", fmt.Sprint(migrations.Generation), "--from-generation", fmt.Sprint(sourceGeneration), "--confirm-node-id", confirmation, "--backup-sha256", strings.Repeat("a", 64)})
				var generation int
				if err := db.Database().QueryRowContext(ctx, "SELECT generation FROM frontiercloud_schema WHERE singleton=1").Scan(&generation); err != nil {
					t.Fatal(err)
				}
				if kind == "success" {
					if e != nil || generation != migrations.Generation {
						t.Fatal("forward migration failed", generation, e)
					}
				} else {
					if e == nil || generation != sourceGeneration {
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
}

func TestPrepareReleaseSourceAdmissionIsExplicit(t *testing.T) {
	if migrations.Generation != 8 {
		t.Skip("explicit generation-8 source admission")
	}
	for _, source := range []int{1, 2, 3, 9, 10} {
		if supportedReleaseSource(source) {
			t.Fatal("undefined source generation admitted", source)
		}
		if err := prepareReleaseCommand([]string{"--confirm-generation", "8", "--from-generation", fmt.Sprint(source), "--confirm-node-id", strings.Repeat("a", 32), "--backup-sha256", strings.Repeat("b", 64)}); err == nil {
			t.Fatal("undefined source reached runtime preparation", source)
		}
	}
	for _, source := range []int{4, 5, 6, 7, 8} {
		if !supportedReleaseSource(source) {
			t.Fatal("retained explicit migration path was dropped", source)
		}
	}
}
