//go:build linux

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/bootstrap"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestStorageSelectedOwnerRealRuntimeRouteAndFence(t *testing.T) {
	for _, mode := range []string{"legacy", "provisioned", "mismatched", "missing-binding", "unbound-marker", "dirty", "wrong-id", "outside-maintenance"} {
		t.Run(mode, func(t *testing.T) { testStorageSelectedOwnerRuntime(t, mode) })
	}
}

func testStorageSelectedOwnerRuntime(t *testing.T, mode string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	c := config.Config{DeploymentMode: config.DeploymentStorage, DataRoot: dir, SecretsDirectory: filepath.Join(dir, "secrets"), TLSEnabled: true, StorageEndpoint: "https://storage.test:8443"}
	if err := bootstrap.InitializeSecrets(c.SecretsDirectory); err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.InitializeMediaContext(ctx, dir); err != nil {
		t.Fatal(err)
	}
	// The native binary and DATA_ROOT owner must match. Bootstrap may set its
	// container application UID even when this isolated fixture runs as root.
	if err := os.Chown(dir, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(dir, "media"), os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(dir, "recordings"), os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "native.db")
	c.SQLitePath, c.DatabaseType = dbPath, config.DatabaseSQLite
	db, err := sqlitestore.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := node.Initialize(ctx, db.Nodes(), c.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	control := node.NewService(db.Nodes(), id, nil)
	initialVolume, err := media.New(filepath.Join(dir, "media"), db.Media(), id)
	if err != nil {
		t.Fatal(err)
	}
	initialRecordings, err := os.OpenRoot(filepath.Join(dir, "recordings"))
	if err != nil {
		t.Fatal(err)
	}
	control.ConfigureVolumes(db.Pool(), initialVolume, initialRecordings)
	initialVolume.ConfigureCluster(db.Nodes(), db.Pool(), control)
	if err = control.InitializeStorage(ctx, c.StorageEndpoint); err != nil {
		t.Fatal(err)
	}
	expectedID := id.ID
	if mode != "legacy" {
		mediaPath := filepath.Join(dir, "media")
		if mode == "dirty" {
			if err = os.WriteFile(filepath.Join(mediaPath, "music", "existing.mp3"), []byte("legacy"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		gate, err := maintenance.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer gate.Close()
		if mode != "outside-maintenance" {
			if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
		}
		expected := id.ID
		if mode == "wrong-id" {
			expected = strings.Repeat("a", 32)
			if expected == id.ID {
				expected = strings.Repeat("b", 32)
			}
		}
		err = prepareEmptyStorageOwner(ctx, c, gate, expected)
		if mode == "dirty" || mode == "wrong-id" || mode == "outside-maintenance" {
			if err == nil {
				t.Fatal("unsafe preparation accepted")
			}
			var markers int
			if err = db.Database().QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_owner_fence`).Scan(&markers); err != nil || markers != 0 {
				t.Fatal("unsafe preparation wrote marker", err, markers)
			}
			return
		}
		if err != nil {
			dataRoot, e := os.OpenRoot(dir)
			if e != nil {
				t.Fatal(err, e)
			}
			clean := sealedtree.CheckEmptyStorageDestination(dataRoot)
			dataRoot.Close()
			for _, d := range []string{"media", "media/music", "media/vido", "media/lyrics", "recordings"} {
				entries, e := os.ReadDir(filepath.Join(dir, d))
				if e != nil {
					t.Logf("fixture %s: %v", d, e)
					continue
				}
				for _, entry := range entries {
					info, _ := entry.Info()
					t.Logf("fixture %s/%s: %v", d, entry.Name(), info.Mode())
				}
			}
			snapshot, e := db.Maintenance().InspectMaintenance(ctx)
			t.Fatalf("prepare failed: %v; empty check: %v; idle=%v inspect=%v", err, clean, snapshot.LogicalIdle, e)
		}
		if err = prepareEmptyStorageOwner(ctx, c, gate, expected); err != nil {
			t.Fatal("idempotent prepare", err)
		}
		if err = gate.Resume(ctx, func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}

		if mode == "mismatched" {
			if _, err = db.Database().ExecContext(ctx, `UPDATE sealed_tree_owner_fence SET fence_tag=? WHERE singleton=1`, strings.Repeat("0", 64)); err != nil {
				t.Fatal(err)
			}
		}
		if mode == "missing-binding" {
			if err = os.Remove(filepath.Join(mediaPath, ".opaque-aliases", ".owner-control-binding")); err != nil {
				t.Fatal(err)
			}
		}
		if mode == "unbound-marker" {
			if _, err = db.Database().ExecContext(ctx, `DELETE FROM sealed_tree_owner_fence WHERE singleton=1`); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = initialVolume.Close(); err != nil {
		t.Fatal(err)
	}
	if err = initialRecordings.Close(); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	restarts := 1
	if mode == "provisioned" {
		restarts = 2
	}
	for restart := 0; restart < restarts; restart++ {
		func() {
			db, err := sqlitestore.OpenExisting(ctx, dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			err = initializeRuntimeSchema(ctx, db, c)
			if err == nil {
				err = checkOpaqueMasterTreeLayout(ctx, db, c)
			}
			if err == nil {
				err = checkOpaqueRegistryIdentity(ctx, db.Nodes(), filepath.Join(dir, "media"), c.SecretsDirectory)
			}
			if err != nil {
				if mode == "mismatched" || mode == "missing-binding" || mode == "unbound-marker" {
					return
				}
				t.Fatalf("restart %d schema and identity prechecks: %v", restart+1, err)
			}
			id, err := node.OpenExisting(ctx, db.Nodes(), c.SecretsDirectory)
			if err != nil {
				t.Fatal(err)
			}
			if id.ID != expectedID || id.Role != "Follower" {
				t.Fatal("reopened Storage identity changed")
			}
			owner, err := openRuntimeOwner(ctx, c, db, id)
			if err != nil {
				if mode == "mismatched" || mode == "missing-binding" || mode == "unbound-marker" {
					return
				}
				t.Fatal(err)
			}
			if owner != nil {
				defer owner.Close()
			}
			volume, err := media.New(filepath.Join(dir, "media"), db.Media(), id)
			if err != nil {
				t.Fatal(err)
			}
			defer volume.Close()
			transport := node.NewTransport()
			defer transport.Close()
			control = node.NewService(db.Nodes(), id, transport)
			recordingRoot, err := os.OpenRoot(filepath.Join(dir, "recordings"))
			if err != nil {
				t.Fatal(err)
			}
			defer recordingRoot.Close()
			control.ConfigureVolumes(db.Pool(), volume, recordingRoot)
			volume.ConfigureCluster(db.Nodes(), db.Pool(), control)
			recordings, err := recording.New(recordingRoot, db.Recordings(), db.Nodes())
			if err != nil {
				t.Fatal(err)
			}
			resolver, err := network.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			router, closeHTTP, err := newRuntimeHTTP(c, runtimeHTTP{Database: db, Identity: id, Media: volume, Control: control, Owner: owner, Recordings: recordings, Resolver: resolver})
			if mode == "mismatched" || mode == "missing-binding" || mode == "unbound-marker" {
				if err == nil {
					closeHTTP()
					t.Fatal("mismatched Owner marker accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer closeHTTP()
			server := httptest.NewTLSServer(router)
			defer server.Close()
			req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/node/selected-upload", strings.NewReader(""))
			if err != nil {
				t.Fatal(err)
			}
			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			want := http.StatusNotFound
			if mode == "provisioned" {
				want = http.StatusForbidden
			}
			if response.StatusCode != want {
				t.Fatalf("mode=%s status=%d want=%d", mode, response.StatusCode, want)
			}
			relayReq, err := http.NewRequest(http.MethodPut, server.URL+"/internal/v1/selected-upload/relay", strings.NewReader(""))
			if err != nil {
				t.Fatal(err)
			}
			relayResponse, err := server.Client().Do(relayReq)
			if err != nil {
				t.Fatal(err)
			}
			relayResponse.Body.Close()
			if relayResponse.StatusCode != want {
				t.Fatalf("mode=%s relay status=%d want=%d", mode, relayResponse.StatusCode, want)
			}
			probe, err := http.NewRequest(http.MethodGet, server.URL+"/internal/v1/opaque-media/"+strings.Repeat("0", 64), nil)
			if err != nil {
				t.Fatal(err)
			}
			probe.Header.Set("X-Fc-Opaque-Probe", strings.Repeat("1", 32))
			probe.Header.Set("X-Media-Capability", "forged")
			probeResponse, err := server.Client().Do(probe)
			if err != nil {
				t.Fatal(err)
			}
			probeResponse.Body.Close()
			probeWant := http.StatusNotFound
			if mode == "provisioned" {
				probeWant = http.StatusUnauthorized
			}
			if probeResponse.StatusCode != probeWant {
				t.Fatalf("mode=%s probe status=%d want=%d", mode, probeResponse.StatusCode, probeWant)
			}
			if mode == "provisioned" {
				lockCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				_, release, err := control.RetirementRequestLease(lockCtx, true)
				if err != nil {
					t.Fatal(err)
				}
				result := make(chan error, 1)
				go func() {
					r, e := http.NewRequestWithContext(lockCtx, http.MethodPut, server.URL+"/api/v1/node/selected-upload", strings.NewReader(""))
					if e != nil {
						result <- e
						return
					}
					res, e := server.Client().Do(r)
					if e == nil {
						res.Body.Close()
						if res.StatusCode != http.StatusForbidden {
							e = fmt.Errorf("unexpected status: %d", res.StatusCode)
						}
					}
					result <- e
				}()
				select {
				case err := <-result:
					release()
					t.Fatal("selected request bypassed retirement lease", err)
				case <-time.After(100 * time.Millisecond):
				}
				release()
				if err := <-result; err != nil {
					t.Fatal("selected request did not resume after retirement lease", err)
				}
			}
		}()
	}
}
