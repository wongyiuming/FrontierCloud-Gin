package httpapi

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourcemigration"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Called only after real fixture byte transfer and managed cleanup completed.
func testAdminDrainRelease(t *testing.T, router *gin.Engine, db store.Store, root string, public *Public, runner *resourcemigration.Runner, taskID string) {
	t.Helper()
	ctx := context.Background()
	opts, e := redis.ParseURL(os.Getenv("FRONTIERCLOUD_TEST_REDIS_URL"))
	if e != nil {
		t.Fatal(e)
	}
	cache := redis.NewClient(opts)
	defer cache.Close()
	cfg := public.settings
	cfg.TLSEnabled = true
	cfg.SecretsDirectory = filepath.Join(root, "secrets")
	key := "drain-release-fixture-key"
	if e = os.WriteFile(filepath.Join(cfg.SecretsDirectory, "admin_key"), []byte(key), 0600); e != nil {
		t.Fatal(e)
	}
	identity, e := node.Initialize(ctx, db.Nodes(), cfg.SecretsDirectory)
	if e != nil {
		t.Fatal(e)
	}
	auth, e := admin.New(cfg, admin.NewRedisCache(cache), db.Admin())
	if e != nil {
		t.Fatal(e)
	}
	a, e := RegisterAdmin(router, cfg, auth, public, identity)
	if e != nil {
		t.Fatal(e)
	}
	RegisterAdminNodes(router, a, runner.Client.(*runnerFaultCaller).client)
	RegisterAdminMigrations(router, a, db.Pool().(store.MigrationAdminRepository), runner)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	client, e := operator.NewNodeClient(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if e = client.UseCA(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})); e != nil {
		t.Fatal(e)
	}
	if e = client.Login(ctx, key); e != nil {
		t.Fatal(e)
	}
	task, e := runner.Repository.MigrationTask(ctx, taskID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = client.ControlMigration(ctx, taskID, "release-drain", task.Revision, task.TargetID, task.SourceID); e == nil {
		t.Fatal("wrong source confirmation")
	}
	if _, e = client.ControlMigration(ctx, taskID, "release-drain", task.Revision-1, task.SourceID, task.TargetID); e == nil {
		t.Fatal("stale drain revision")
	}
	for range 2 {
		if _, e = client.ControlMigration(ctx, taskID, "release-drain", task.Revision, task.SourceID, task.TargetID); e != nil {
			t.Fatal(e)
		}
	}
	if binary := os.Getenv("FRONTIERCLOUD_TEST_FC_BINARY"); binary != "" {
		caPath := filepath.Join(t.TempDir(), "public-ca.pem")
		if e = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); e != nil {
			t.Fatal(e)
		}
		commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		args := []string{"node", "migrate", "release-drain", taskID, "--master", server.URL, "--ca-file", caPath, "--credential-stdin", "--task-revision", fmt.Sprint(task.Revision), "--confirm-source-id", task.SourceID, "--confirm-target-id", task.TargetID}
		command := exec.CommandContext(commandCtx, binary, args...)
		command.Stdin = strings.NewReader(key + "\n")
		var output, diagnostics bytes.Buffer
		command.Stdout = &output
		command.Stderr = &diagnostics
		if e = command.Run(); e != nil || !strings.Contains(output.String(), "This task-owned drain was released") || strings.Contains(output.String()+diagnostics.String(), key) {
			t.Fatal("CLI drain release", e)
		}
	}

}
