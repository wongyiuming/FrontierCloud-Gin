//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestLocalHistoryIDsOfflineResumeAndScope(t *testing.T) {
	for _, total := range []int{0, 300} {
		t.Run(fmt.Sprint(total), func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "business.sqlite")
			fencePath := filepath.Join(dir, "tree")
			if err := os.Mkdir(fencePath, 0700); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=busy_timeout(5000)")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			data, err := os.ReadFile("../../migrations/sqlite/0011-schema.json")
			if err != nil {
				t.Fatal(err)
			}
			var old struct {
				Generation int      `json:"generation"`
				Statements []string `json:"statements"`
			}
			if err = json.Unmarshal(data, &old); err != nil || old.Generation != 11 {
				t.Fatal("historic schema", err)
			}
			for _, stmt := range old.Statements {
				if _, err = db.ExecContext(ctx, stmt); err != nil {
					t.Fatal(err)
				}
			}
			for _, item := range []struct {
				gen       int
				name, sum string
			}{{8, migrations.S3Name, migrations.S3Checksum}, {9, migrations.PublicRoutingName, migrations.PublicRoutingChecksum}, {10, migrations.SealedTreeName, migrations.SealedTreeChecksum}, {11, migrations.LegacyReadIntentName, migrations.LegacyReadIntentChecksum}} {
				if _, err = db.ExecContext(ctx, `INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES(?,?,?,123)`, item.gen, item.name, item.sum); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = db.ExecContext(ctx, `INSERT INTO frontiercloud_schema(singleton,generation,created_at) VALUES(1,11,123)`); err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(dbPath, 0600); err != nil {
				t.Fatal(err)
			}
			gate, err := maintenance.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Close()
			if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			c := config.Config{DataRoot: dir, SQLitePath: dbPath, DatabaseType: config.DatabaseSQLite, SecretsDirectory: filepath.Join(dir, "secrets")}
			if err = deployment.Bind(ctx, c, nil); err != nil {
				t.Fatal(err)
			}
			v, err := vault.Open(c.SecretsDirectory)
			if err != nil {
				t.Fatal(err)
			}
			key, err := v.Seal(protocol.Encode(bytes.Repeat([]byte{5}, 32)))
			if err != nil {
				t.Fatal(err)
			}
			node := strings.Repeat("f", 32)
			if _, err = db.ExecContext(ctx, `INSERT INTO node_identity(singleton,node_id,role,endpoint,private_key,created_at) VALUES(1,?,'Master','',?,123)`, node, key); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < total; i++ {
				kind := "media"
				if i%2 == 1 {
					kind = "recording_lyric"
				}
				if _, err = db.ExecContext(ctx, `INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES(?,?,?,?,1)`, kind, fmt.Sprintf("%064x", i+1), fmt.Sprintf("%032x", i+1), nil); err != nil {
					t.Fatal(err)
				}
			}
			if err = schema.Initialize(ctx, db, "sqlite"); err != nil {
				t.Fatal("generation 11 to 12", err)
			}
			tree := fixture(t)
			rootID := strings.Repeat("a", 64)
			if err = initializeExistingSQLiteOffline(ctx, c, gate, tree, rootID, fencePath); err != nil {
				t.Fatal(err)
			}
			s, err := OpenSQLite(ctx, db, tree, rootID)
			if err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(fencePath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if _, err = OpenFence(ctx, s, root, fencePath); err != nil {
				t.Fatal(err)
			}
			run := func() (HistoricalMediaIDScope, error) {
				return importLocalHistoryIDsOffline(ctx, gate, dir, dbPath, s, root, v, node)
			}
			if total > 0 {
				if _, err = db.ExecContext(ctx, `CREATE TRIGGER fail_second_history BEFORE INSERT ON sealed_tree_encryption_ids WHEN (SELECT COUNT(*) FROM sealed_tree_encryption_ids)>=261 BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
					t.Fatal(err)
				}
				if _, err = run(); err == nil {
					t.Fatal("injected failure accepted")
				}
				var count int
				if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids`).Scan(&count); err != nil || count <= 1 {
					t.Fatal("first batch did not commit", count, err)
				}
				if _, err = db.ExecContext(ctx, `DROP TRIGGER fail_second_history`); err != nil {
					t.Fatal(err)
				}
				// Reopen the store and fence as a new runtime would after a crash.
				if err = root.Close(); err != nil {
					t.Fatal(err)
				}
				s, err = OpenSQLite(ctx, db, tree, rootID)
				if err != nil {
					t.Fatal(err)
				}
				root, err = os.OpenRoot(fencePath)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				if _, err = OpenFence(ctx, s, root, fencePath); err != nil {
					t.Fatal(err)
				}
				if _, err = db.ExecContext(ctx, `INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES('media',?,?,NULL,1)`, fmt.Sprintf("%064x", total+1), fmt.Sprintf("%032x", total+1)); err != nil {
					t.Fatal(err)
				}
				if _, err = run(); err == nil {
					t.Fatal("changed source accepted after checkpoint")
				}
				if _, err = db.ExecContext(ctx, `DELETE FROM media_encryption WHERE file_id=?`, fmt.Sprintf("%032x", total+1)); err != nil {
					t.Fatal(err)
				}
			}
			scope, err := run()
			if err != nil {
				t.Fatal(err)
			}
			if scope.Empty != (total == 0) || scope.Batches != uint64((total+255)/256) {
				t.Fatal("incorrect completed scope", scope)
			}
			retry, err := run()
			if err != nil || retry != scope {
				t.Fatal("retry changed scope", retry, err)
			}
			var count int
			if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM media_encryption WHERE descriptor_json IS NULL`).Scan(&count); err != nil || count != total {
				t.Fatal("source changed", count, err)
			}
			for i := 0; i < total; i++ {
				id := fmt.Sprintf("%032x", i+1)
				tag, err := s.mediaFileTag("id", id)
				if err != nil {
					t.Fatal(err)
				}
				if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, tag).Scan(&count); err != nil || count != 1 {
					t.Fatal("missing durable ID reservation", err)
				}
			}
			if _, err = db.ExecContext(ctx, `UPDATE node_identity SET node_id=? WHERE singleton=1`, strings.Repeat("e", 32)); err != nil {
				t.Fatal(err)
			}
			if _, err = run(); err == nil {
				t.Fatal("changed identity accepted")
			}
		})
	}
}
