package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
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
