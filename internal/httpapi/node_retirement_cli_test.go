package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNodeRetirementCLIRealTLSRedisAndAuthenticatedPeerObservation(t *testing.T) {
	redisURL := os.Getenv("FRONTIERCLOUD_TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("requires isolated Redis")
	}
	opts, e := redis.ParseURL(redisURL)
	if e != nil {
		t.Fatal(e)
	}
	cache := redis.NewClient(opts)
	defer cache.Close()
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, mdb, dir, public, master := clusterFixture(t, "https://master.test", transport, true)
	_, sdb, _, _, storage := clusterFixture(t, "https://storage.test", transport, true)
	if _, e = master.Promote(ctx, "Master", "https://master.test", store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = storage.Promote(ctx, "Follower", "https://storage.test", 0, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	pair, e := storage.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	rid, e := master.ImportPair(ctx, pair, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	rel, e := mdb.Nodes().Relationship(ctx, rid)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = sdb.Media().EnsureObjects(ctx, []store.MediaObject{{Path: "music/cli/missing.mp3", Kind: "audio"}}); e != nil {
		t.Fatal(e)
	}
	cfg := public.settings
	cfg.TLSEnabled = true
	cfg.SecretsDirectory = filepath.Join(dir, "secrets")
	key := "retirement-cli-integration-fixture-key"
	if e = os.WriteFile(filepath.Join(cfg.SecretsDirectory, "admin_key"), []byte(key), 0600); e != nil {
		t.Fatal(e)
	}
	identity, e := node.Initialize(ctx, mdb.Nodes(), cfg.SecretsDirectory)
	if e != nil {
		t.Fatal(e)
	}
	auth, e := admin.New(cfg, admin.NewRedisCache(cache), mdb.Admin())
	if e != nil {
		t.Fatal(e)
	}
	a, e := RegisterAdmin(router, cfg, auth, public, identity)
	if e != nil {
		t.Fatal(e)
	}
	RegisterAdminNodes(router, a, master)
	RegisterAdminMigrations(router, a, mdb.Pool().(store.MigrationAdminRepository))
	RegisterAdminRetirement(router, a, &noderetirement.Service{Repository: mdb.Pool().(store.RetirementRepository), Nodes: mdb.Nodes(), Client: master})
	server := httptest.NewTLSServer(router)
	defer server.Close()
	client, e := operator.NewNodeClient(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if e = client.UseCA(ca); e != nil {
		t.Fatal(e)
	}
	if e = client.Login(ctx, key); e != nil {
		t.Fatal(e)
	}
	report, e := client.RetirementCheck(ctx, rel.PeerID)
	if e != nil || !report.PreflightOnly || !report.ObservationComplete || report.Master.RelationshipID != rid || report.Peer.RelationshipID != rid {
		t.Fatal("CLI bypassed or lost native report", report, e)
	}
	found := false
	for _, c := range report.Concerns {
		if c.Code == "expected_missing" && c.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("CLI omitted actual missing file", report)
	}
	client.Close()
	if _, e = client.RetirementCheck(ctx, rel.PeerID); e == nil {
		t.Fatal("logged-out client retained authorization")
	}
	if binary := os.Getenv("FRONTIERCLOUD_TEST_FC_BINARY"); binary != "" {
		caPath := filepath.Join(t.TempDir(), "trusted-ca.pem")
		if e = os.WriteFile(caPath, ca, 0600); e != nil {
			t.Fatal(e)
		}
		taskID := strings.Repeat("f", 32)
		target := strings.Repeat("c", 32)
		if _, e = mdb.Database().Exec("INSERT INTO migration_tasks(task_id,master_id,source_id,target_id,source_relationship,target_relationship,plan_sha256,plan,state,revision,object_count,total_bytes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'{}','queued',1,0,0,1,1)", taskID, identity.ID, rel.PeerID, target, rid, strings.Repeat("d", 32), strings.Repeat("e", 64)); e != nil {
			t.Fatal(e)
		}
		if _, e = mdb.Database().Exec("INSERT INTO migration_capacity(task_id,member_id,reserved_bytes,updated_at) VALUES (?,?,7,1)", taskID, target); e != nil {
			t.Fatal(e)
		}
		if _, e = mdb.Database().Exec("INSERT INTO migration_drains(member_id,owner_id,reason,created_at) VALUES (?,?,'migration',1)", rel.PeerID, taskID); e != nil {
			t.Fatal(e)
		}
		invoke := func(action string, revision int64, want int) []byte {
			args := []string{"node", "migrate", action, taskID, "--master", server.URL, "--ca-file", caPath, "--credential-stdin", "--json"}
			if action != "status" {
				args = append(args, "--task-revision", fmt.Sprint(revision), "--confirm-source-id", rel.PeerID, "--confirm-target-id", target)
			}
			commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			command := exec.CommandContext(commandCtx, binary, args...)
			command.Stdin = strings.NewReader(key + "\n")
			var output, diagnostics bytes.Buffer
			command.Stdout = &output
			command.Stderr = &diagnostics
			err := command.Run()
			code := 0
			if err != nil {
				var exited *exec.ExitError
				if !errors.As(err, &exited) {
					t.Fatal(err)
				}
				code = exited.ExitCode()
			}
			if code != want || strings.Contains(output.String()+diagnostics.String(), key) {
				t.Fatal("migration CLI execution or credential handling", action, code)
			}
			return output.Bytes()
		}
		rawStatus := invoke("status", 0, 0)
		var migrationStatus store.MigrationStatus
		if json.Unmarshal(rawStatus, &migrationStatus) != nil || migrationStatus.Task.ID != taskID || migrationStatus.RetirementReady {
			t.Fatal("migration CLI status")
		}
		invoke("pause", 1, 0)
		invoke("resume", 1, 2)
		invoke("resume", 2, 0)
		invoke("pause", 3, 0)
		invoke("cancel", 4, 0)
		if _, e = mdb.Database().Exec("UPDATE migration_tasks SET error_code='cancel_cleanup' WHERE task_id=?", taskID); e != nil {
			t.Fatal(e)
		}
		invoke("retry", 5, 0)
		var reserved, drains int64
		if e = mdb.Database().QueryRow("SELECT reserved_bytes FROM migration_capacity WHERE task_id=?", taskID).Scan(&reserved); e != nil || reserved != 7 {
			t.Fatal("CLI released cleanup reservation", reserved, e)
		}
		if e = mdb.Database().QueryRow("SELECT COUNT(*) FROM migration_drains WHERE member_id=? AND owner_id=?", rel.PeerID, taskID).Scan(&drains); e != nil || drains != 1 {
			t.Fatal("CLI released draining", drains, e)
		}
		for _, structured := range []bool{true, false} {
			args := []string{"node", "retire", "check", rel.PeerID, "--master", server.URL, "--ca-file", caPath, "--credential-stdin"}
			if structured {
				args = append(args, "--json")
			}
			commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			command := exec.CommandContext(commandCtx, binary, args...)
			command.Stdin = strings.NewReader(key + "\n")
			var output, diagnostics bytes.Buffer
			command.Stdout = &output
			command.Stderr = &diagnostics
			err := command.Run()
			cancel()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 1 || strings.Contains(output.String()+diagnostics.String(), key) {
				t.Fatal("CLI execution or credential handling", err)
			}
			if structured {
				var report noderetirement.Report
				if json.Unmarshal(output.Bytes(), &report) != nil || report.MemberID != rel.PeerID || !report.ObservationComplete || !report.PreflightOnly {
					t.Fatal("CLI structured report")
				}
			} else if !strings.Contains(output.String(), "Preflight only: true") || !strings.Contains(output.String(), "expected_missing") {
				t.Fatal("CLI human report")
			}
		}
	}
	current, e := mdb.Nodes().Relationship(ctx, rid)
	if e != nil || current.State != "active" {
		t.Fatal("CLI check revoked relationship", current, e)
	}
}
