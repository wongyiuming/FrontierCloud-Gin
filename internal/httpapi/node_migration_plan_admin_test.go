package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourcemigration"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func testAdminMigrationPlanning(t *testing.T, router *gin.Engine, db store.Store, root string, public *Public, master *node.Service, sourceRoot string, catalog store.MigrationCatalog, payloads map[string][]byte) {
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
	key := "migration-plan-fixture-admin-key"
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
	RegisterAdminNodes(router, a, master)
	runner := &resourcemigration.Runner{Repository: db.Pool().(store.MigrationRepository), Nodes: db.Nodes(), Client: master}
	planner, e := resourcemigration.NewPlanner(ctx, runner)
	if e != nil {
		t.Fatal(e)
	}
	defer planner.Close()
	RegisterAdminMigrationPlanning(router, a, planner)
	server := httptest.NewTLSServer(router)
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, e := operator.NewNodeClient(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if e = client.UseCA(ca); e != nil {
		t.Fatal(e)
	}
	if e = client.Login(ctx, key); e != nil {
		t.Fatal(e)
	}
	rawClient := server.Client()
	endpoint := server.URL + "/api/v1/media/admin/nodes/migration-plans"
	post := func(body, csrf string) int {
		req, e := http.NewRequest("POST", endpoint, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		resp, e := rawClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable response")
		}
		return resp.StatusCode
	}
	body, _ := json.Marshal(map[string]any{"request_id": strings.Repeat("1", 32), "source_id": catalog.Source.ID, "target_id": catalog.Target.ID})
	if code := post(string(body), ""); code != 401 {
		t.Fatal("anonymous plan", code)
	}
	rawClient.Jar, _ = cookiejar.New(nil)
	login, e := rawClient.PostForm(server.URL+"/api/v1/media/admin/elevate", url.Values{"token": {key}})
	if e != nil {
		t.Fatal(e)
	}
	login.Body.Close()
	if login.StatusCode != 200 {
		t.Fatal("fixture login", login.StatusCode)
	}
	if code := post(string(body), ""); code != 403 {
		t.Fatal("plan without CSRF", code)
	}
	parsed, _ := url.Parse(endpoint)
	csrf := ""
	for _, cookie := range rawClient.Jar.Cookies(parsed) {
		if cookie.Name == cfg.CSRFCookieName() {
			csrf = cookie.Value
		}
	}
	if csrf == "" {
		t.Fatal("missing fixture CSRF")
	}
	for _, extra := range []string{`,"disk_proofs":[]}`, `,"target_physical_free":999999999999}`, `,"force":true}`} {
		if code := post(strings.TrimSuffix(string(body), "}")+extra, csrf); code != 422 {
			t.Fatal("client proof accepted", code)
		}
	}
	wait := func(id, state string) resourcemigration.PlanView {
		deadline := time.Now().Add(20 * time.Second)
		for {
			v, e := client.MigrationPlanStatus(ctx, id, "")
			if e != nil {
				t.Fatal(e)
			}
			if v.State == state {
				return v
			}
			if time.Now().After(deadline) {
				t.Fatal("plan state", v.State, v.ErrorCode)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	v, e := client.CreateMigrationPlan(ctx, strings.Repeat("2", 32), catalog.Source.ID, catalog.Target.ID)
	if e != nil {
		t.Fatal(e)
	}
	v = wait(v.ID, "ready")
	// Replace one disposable source with same-length bytes without changing
	// Master metadata. Fresh start must reject the previously reviewed hashes.
	object := catalog.Objects[0]
	file := filepath.Join(sourceRoot, "media", filepath.FromSlash(object.Path))
	changed := append([]byte(nil), payloads[object.Path]...)
	changed[len(changed)-1] ^= 0x31
	if e = os.WriteFile(file, changed, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = client.StartMigrationPlan(ctx, v.ID, v.ReviewSHA, catalog.Source.ID, catalog.Target.ID); e != nil {
		t.Fatal(e)
	}
	wait(v.ID, "failed")
	if _, e = runner.Repository.MigrationTask(ctx, v.ID); e == nil {
		t.Fatal("changed source created durable task")
	}
	if e = os.WriteFile(file, payloads[object.Path], 0600); e != nil {
		t.Fatal(e)
	}
	invoke := func(args ...string) resourcemigration.PlanView {
		binary := os.Getenv("FRONTIERCLOUD_TEST_FC_BINARY")
		if binary == "" {
			t.Fatal("compiled CLI not provided")
		}
		caPath := filepath.Join(t.TempDir(), "test-ca.pem")
		if e = os.WriteFile(caPath, ca, 0600); e != nil {
			t.Fatal(e)
		}
		args = append(args, "--master", server.URL, "--ca-file", caPath, "--credential-stdin", "--json")
		command := exec.CommandContext(ctx, binary, args...)
		command.Stdin = strings.NewReader(key + "\n")
		var output, diagnostics bytes.Buffer
		command.Stdout = &output
		command.Stderr = &diagnostics
		if e = command.Run(); e != nil {
			t.Fatalf("compiled CLI failed: %v; %s", e, diagnostics.String())
		}
		if strings.Contains(output.String()+diagnostics.String(), key) {
			t.Fatal("credential leaked")
		}
		var result resourcemigration.PlanView
		if e = json.Unmarshal(output.Bytes(), &result); e != nil {
			t.Fatal(e)
		}
		return result
	}
	if os.Getenv("FRONTIERCLOUD_TEST_FC_BINARY") != "" {
		v = invoke("node", "migrate", "plan", "--from", catalog.Source.ID, "--to", catalog.Target.ID)
		v = wait(v.ID, "ready")
		view := invoke("node", "migrate", "plan-status", "--plan", v.ID)
		if view.ReviewSHA != v.ReviewSHA {
			t.Fatal("CLI changed review")
		}
		invoke("node", "migrate", "start", "--plan", v.ID, "--review-sha256", v.ReviewSHA, "--confirm-source-id", catalog.Source.ID, "--confirm-target-id", catalog.Target.ID)
	} else {
		t.Log("compiled CLI subcase not executed: FRONTIERCLOUD_TEST_FC_BINARY is unset")
		v, e = client.CreateMigrationPlan(ctx, strings.Repeat("3", 32), catalog.Source.ID, catalog.Target.ID)
		if e != nil {
			t.Fatal(e)
		}
		v = wait(v.ID, "ready")
		if _, e = client.StartMigrationPlan(ctx, v.ID, v.ReviewSHA, catalog.Source.ID, catalog.Target.ID); e != nil {
			t.Fatal(e)
		}
	}
	v = wait(v.ID, "started")
	if v.Task == nil || v.Task.State != "queued" {
		t.Fatal(v)
	}
	replay, e := client.StartMigrationPlan(ctx, v.ID, v.ReviewSHA, catalog.Source.ID, catalog.Target.ID)
	if e != nil || replay.Task == nil || replay.Task.ID != v.ID {
		t.Fatal("start replay", e)
	}
	if e = runner.Run(ctx, v.ID, strings.Repeat("7", 32)); e != nil {
		t.Fatal("planned task execution", e)
	}
	for _, o := range catalog.Objects {
		resource, e := db.Pool().Resource(ctx, o.ID)
		if e != nil || resource.MemberID != catalog.Target.ID {
			t.Fatal("plan lost logical owner", e)
		}
		reader, e := master.ReadGlobalMedia(ctx, resource)
		if e != nil {
			t.Fatal(e)
		}
		actual, e := io.ReadAll(reader)
		reader.Close()
		if e != nil || !bytes.Equal(actual, payloads[o.Path]) {
			t.Fatal("planned target bytes", e)
		}
	}
}
