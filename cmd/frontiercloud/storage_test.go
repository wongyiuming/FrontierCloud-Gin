package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/bootstrap"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestStorageOnlyRoutesIdentityAndOneUsePackageWithoutBusinessDependencies(t *testing.T) {
	ctx, dir := context.Background(), t.TempDir()
	c := config.Config{DeploymentMode: config.DeploymentStorage, DataRoot: dir, SecretsDirectory: filepath.Join(dir, "secrets"), TLSEnabled: true, StorageEndpoint: "https://storage.test:8443"}
	if err := bootstrap.InitializeSecrets(c.SecretsDirectory); err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.InitializeMediaContext(ctx, dir); err != nil {
		t.Fatal(err)
	}
	db, err := sqlitestore.Open(filepath.Join(dir, "native.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := node.Initialize(ctx, db.Nodes(), c.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := media.New(filepath.Join(dir, "media"), db.Media(), id)
	if err != nil {
		t.Fatal(err)
	}
	defer volume.Close()
	transport := node.NewTransport()
	defer transport.Close()
	control := node.NewService(db.Nodes(), id, transport)
	root, err := os.OpenRoot(filepath.Join(dir, "recordings"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	control.ConfigureVolumes(db.Pool(), volume, root)
	volume.ConfigureCluster(db.Nodes(), db.Pool(), control)
	if err := control.InitializeStorage(ctx, c.StorageEndpoint); err != nil {
		t.Fatal(err)
	}
	if id.Role != "Follower" {
		t.Fatal("durable wire identity did not become storage discriminator", id.Role)
	}
	before := id.ID
	if err := control.InitializeStorage(ctx, c.StorageEndpoint); err != nil || id.ID != before {
		t.Fatal("restart changed identity", err)
	}
	if err := control.InitializeStorage(ctx, "https://another.test:8443"); err == nil {
		t.Fatal("silent endpoint rewrite")
	}
	storage, err := recording.New(root, db.Recordings(), db.Nodes())
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	router, closeHTTP, err := newRuntimeHTTP(c, runtimeHTTP{Database: db, Identity: id, Media: volume, Control: control, Recordings: storage, Resolver: resolver})
	if err != nil {
		t.Fatal("storage incorrectly required Redis/accounts/security/updater", err)
	}
	defer closeHTTP()
	for _, path := range []string{"/", "/api/v1/media", "/api/v1/media/admin", "/api/v1/media/admin/nodes", "/api/v1/media/admin/nodes/release", "/api/v1/karaoke/login", "/static/js/player.js", "/internal/v1/cluster-update/status", "/internal/v1/cluster-update/start"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatal("business/updater route exposed", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/health/ready", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var output bytes.Buffer
	if err := printStoragePair(ctx, control, db.Nodes(), &output); err != nil {
		t.Fatal(err)
	}
	var envelope node.Envelope
	decoder := json.NewDecoder(&output)
	decoder.UseNumber()
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	key, _ := envelope.Payload["public_key"].(string)
	if err := protocol.Verify(key, envelope.Payload, envelope.Signature); err != nil {
		t.Fatal("printed package is not signed", err)
	}
	if envelope.Payload["node_id"] != before || envelope.Payload["endpoint"] != c.StorageEndpoint {
		t.Fatal(envelope.Payload)
	}
	if _, ok := envelope.Payload["private_key"]; ok {
		t.Fatal("private key printed")
	}
}
