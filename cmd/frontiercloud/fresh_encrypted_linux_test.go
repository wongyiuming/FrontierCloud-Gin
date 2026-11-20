//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
)

func TestFreshEncryptedRuntime(t *testing.T) {
	for _, role := range []string{"Master", "Follower"} {
		t.Run(role, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			c := config.Config{
				DeploymentMode:   config.DeploymentBusiness,
				DatabaseType:     config.DatabaseSQLite,
				TLSEnabled:       true,
				DataRoot:         filepath.Join(root, "data"),
				SecretsDirectory: filepath.Join(root, "secrets"),
				AdminOrigin:      "https://master.test",
				StorageEndpoint:  "https://storage.test",
			}
			c.SQLitePath = filepath.Join(c.DataRoot, "frontiercloud.db")
			if role == "Follower" {
				c.DeploymentMode = config.DeploymentStorage
			}
			for _, path := range []string{"media", "recordings"} {
				if err := os.MkdirAll(filepath.Join(c.DataRoot, path), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(c.SecretsDirectory, 0700); err != nil {
				t.Fatal(err)
			}
			gate, err := maintenance.Open(c.DataRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Close()
			var stableID string
			for attempt := 0; attempt < 2; attempt++ {
				if err := prepareFreshEncryptedRuntime(ctx, c, gate); err != nil {
					t.Fatal(err)
				}
				db, err := openRuntimeStore(ctx, c)
				if err != nil {
					t.Fatal(err)
				}
				id, err := openRuntimeIdentity(ctx, db, c)
				if err != nil || id.Role != role || (attempt > 0 && stableID != id.ID) {
					t.Fatalf("fresh identity failed on attempt %d: %v", attempt, err)
				}
				stableID = id.ID
				owner, err := openRuntimeOwner(ctx, c, db, id)
				if err != nil || owner == nil {
					t.Fatalf("missing prepared %s volume: %v", role, err)
				}
				owner.Close()
				tree, closeTree, err := openOpaqueMasterTree(ctx, db, c)
				if err != nil || (tree != nil) != (role == "Master") {
					t.Fatalf("unexpected encrypted tree for %s: %v", role, err)
				}
				if closeTree != nil {
					closeTree()
				}
				if enabled, err := gate.Enabled(); err != nil || enabled {
					t.Fatalf("bootstrap did not release maintenance: %v", err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
