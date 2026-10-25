package operator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

type fakeRunner struct {
	calls              []string
	config             Config
	existingVolumes    string
	existingContainers string
	pullFailure        bool
	requireNoWrites    bool
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if r.requireNoWrites && (strings.Contains(call, " pull ") || strings.Contains(call, " up ") || strings.Contains(call, " exec ")) {
		return nil, errors.New("unexpected write")
	}
	if strings.Contains(call, " config ") {
		cfg := r.config
		if strings.Contains(call, ImagesFile) {
			raw, e := os.ReadFile(filepath.Join(filepath.Dir(cfg.Services["web"].Volumes[0].Source), ImagesFile))
			if e != nil {
				return nil, e
			}
			var override struct {
				Services map[string]struct {
					Image string `json:"image"`
				} `json:"services"`
			}
			_ = json.Unmarshal(raw, &override)
			copy := map[string]Service{}
			for name, s := range cfg.Services {
				s.Image = override.Services[name].Image
				copy[name] = s
			}
			cfg.Services = copy
		}
		return json.Marshal(cfg)
	}
	if strings.Contains(call, " ps ") {
		return []byte(r.existingContainers), nil
	}
	if strings.Contains(call, " volume ls ") {
		return []byte(r.existingVolumes), nil
	}
	if strings.Contains(call, " pull ") && r.pullFailure {
		return nil, errors.New("secret=must-not-escape")
	}
	if strings.Contains(call, "image inspect") {
		return []byte(`["redis@sha256:` + strings.Repeat("b", 64) + `"]`), nil
	}
	if strings.Contains(call, " info ") {
		return []byte(`{"OSType":"linux","Architecture":"x86_64","ServerVersion":"29.1.3"}`), nil
	}
	if strings.Contains(call, " compose version ") {
		return []byte("2.40.3"), nil
	}
	if strings.HasSuffix(call, " certificate-status") {
		return []byte(`{"enabled":false,"controller_running":true,"state":"DISABLED"}`), nil
	}
	return nil, nil
}

type fakeImages struct {
	calls   []string
	failure string
	pinned  map[string]string
}

func (i *fakeImages) Prove(_ context.Context, target, component, arch string) (release.ImageProof, error) {
	i.calls = append(i.calls, target+":"+component)
	if component == i.failure {
		return release.ImageProof{}, release.ErrImagePermission
	}
	if target == "latest" {
		target = strings.Repeat("a", 40)
	}
	image := "ghcr.io/wongyiuming/frontiercloud-gin-" + component + "@sha256:" + strings.Repeat("c", 64)
	if pinned := i.pinned[target+":"+component]; pinned != "" {
		image = pinned
	}
	return release.ImageProof{Image: image, Revision: target, Platform: "linux/" + arch, Generation: migrations.Generation}, nil
}

type fakeEvidence struct{ valid bool }

func (e fakeEvidence) Artifact(_ context.Context, target string) (map[string]any, error) {
	return map[string]any{"publishable": e.valid, "sha": target, "ci_sha": strings.Repeat("d", 40)}, nil
}
func fixture(t *testing.T) (*Deployment, *fakeRunner) {
	t.Helper()
	root := t.TempDir()
	dep, e := New(root, "master", "sqlite")
	if e != nil {
		t.Fatal(e)
	}
	runner := &fakeRunner{config: Config{Name: "fc-test", Services: map[string]Service{
		"web":   {Image: "ghcr.io/wongyiuming/frontiercloud-gin-web:latest", Environment: map[string]string{"DB_TYPE": "sqlite", "SERVER_NAME": "localhost", "TLS_ENABLED": "false"}, Volumes: []Mount{{Type: "bind", Source: filepath.Join(root, "data"), Target: "/app/data"}}},
		"nginx": {Image: "ghcr.io/wongyiuming/frontiercloud-gin-nginx:latest"}, "redis": {Image: "redis:7.4.11-alpine"},
	}, Volumes: map[string]struct {
		Name     string `json:"name"`
		External bool   `json:"external"`
	}{"runtime_secrets": {Name: "fc-test_runtime_secrets"}}}}
	dep.Runner = runner
	return dep, runner
}
func TestInstallPinsOneRevisionAndInfrastructureBeforeStarting(t *testing.T) {
	d, r := fixture(t)
	images := &fakeImages{}
	receipt, e := d.Install(context.Background(), "", "amd64", fakeEvidence{true}, images)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(images.calls, []string{"latest:web", strings.Repeat("a", 40) + ":nginx"}) {
		t.Fatal(images.calls)
	}
	if receipt.Revision != strings.Repeat("a", 40) || receipt.ServiceImages["redis"] != "redis@sha256:"+strings.Repeat("b", 64) {
		t.Fatal(receipt)
	}
	if !strings.Contains(r.calls[len(r.calls)-3], "--no-build --pull never --wait") || !strings.HasSuffix(r.calls[len(r.calls)-1], " certificate-ready") {
		t.Fatal(r.calls)
	}
	opened, got, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	opened.Runner = r
	if _, e = opened.ValidateReceipt(context.Background(), got); e != nil {
		t.Fatal(e)
	}
	r.config.Name = "another-project"
	if _, e = opened.ValidateReceipt(context.Background(), got); e == nil {
		t.Fatal("project drift accepted")
	}
}

func TestExistingGinComposeReceiptRetainsItsFiles(t *testing.T) {
	for _, database := range []string{"sqlite", "mysql"} {
		t.Run(database, func(t *testing.T) {
			d, err := New(t.TempDir(), "master", database)
			if err != nil {
				t.Fatal(err)
			}
			files := append([]string(nil), d.Files...)
			files[0] = "docker-compose.gin.yaml"
			r := Receipt{Version: ConfigurationVersion, Role: "master", Database: database, Project: "retained", Revision: strings.Repeat("a", 40), Files: files, State: "ready"}
			if err = exclusiveJSON(filepath.Join(d.Directory, ReceiptFile), r); err != nil {
				t.Fatal(err)
			}
			opened, got, err := Open(d.Directory)
			if err != nil || !reflect.DeepEqual(opened.Files, files) || !reflect.DeepEqual(got.Files, files) {
				t.Fatal("existing Compose selection changed", err)
			}
		})
	}
}

func TestInstallRefusesDataIdentityVolumesAndExistingContainers(t *testing.T) {
	for _, kind := range []string{"database", "media", "identity", "volume", "container", "symlink", "changed-mount"} {
		t.Run(kind, func(t *testing.T) {
			d, r := fixture(t)
			data := filepath.Join(d.Directory, "data")
			switch kind {
			case "changed-mount":
				if e := os.Mkdir(data, 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(data, "frontiercloud.db"), []byte("preserve"), 0600); e != nil {
					t.Fatal(e)
				}
				web := r.config.Services["web"]
				web.Volumes[0].Source = filepath.Join(d.Directory, "new-data")
				r.config.Services["web"] = web
			case "volume":
				r.existingVolumes = "fc-test_runtime_secrets\n"
			case "container":
				r.existingContainers = "container-id"
			case "symlink":
				if e := os.Symlink(t.TempDir(), data); e != nil {
					t.Skip("symlink unavailable")
				}
			default:
				if e := os.Mkdir(data, 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(data, kind), []byte("preserve"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			images := &fakeImages{}
			if _, e := d.Install(context.Background(), "", "amd64", fakeEvidence{true}, images); e == nil {
				t.Fatal("nonempty installation accepted")
			}
			if len(images.calls) != 0 {
				t.Fatal("network before target guard")
			}
			for _, call := range r.calls {
				if strings.Contains(call, " pull ") || strings.Contains(call, " up ") {
					t.Fatal(call)
				}
			}
		})
	}
}
func TestFailedProofOrPullNeverInitializesOrBuilds(t *testing.T) {
	for _, kind := range []string{"evidence", "component", "pull"} {
		t.Run(kind, func(t *testing.T) {
			d, r := fixture(t)
			images := &fakeImages{}
			if kind == "component" {
				images.failure = "nginx"
			}
			r.pullFailure = kind == "pull"
			_, e := d.Install(context.Background(), "", "amd64", fakeEvidence{kind != "evidence"}, images)
			if e == nil {
				t.Fatal("failure accepted")
			}
			if strings.Contains(e.Error(), "must-not-escape") {
				t.Fatal("credential leaked")
			}
			for _, call := range r.calls {
				if strings.Contains(call, " up ") || strings.Contains(call, " build ") {
					t.Fatal(call)
				}
			}
			if _, e := os.Stat(filepath.Join(d.Directory, ReceiptFile)); !os.IsNotExist(e) {
				t.Fatal("published failed receipt", e)
			}
		})
	}
}
func TestDoctorPerformsNoMutationsAndDoesNotClaimInboundProof(t *testing.T) {
	d, r := fixture(t)
	r.requireNoWrites = true
	report := d.Doctor(context.Background())
	if !report.ReadOnly {
		t.Fatal(report)
	}
	for _, path := range []string{ReceiptFile, ImagesFile, ".fc-install.lock", OperationLock, "data"} {
		if _, e := os.Stat(filepath.Join(d.Directory, path)); !os.IsNotExist(e) {
			t.Fatal("doctor mutated filesystem", path)
		}
	}
	for _, check := range report.Checks {
		if check.Item == "database_generation" && check.State != "unverified" {
			t.Fatal("database opened by doctor")
		}
	}
}
func TestComposeVersionGate(t *testing.T) {
	for _, value := range []string{"2.24.0", "v2.40.3", "3.0.0"} {
		if !ComposeVersion(value) {
			t.Fatal(value)
		}
	}
	for _, value := range []string{"2.23.9", "1.29.2", "unknown", "2.x.0"} {
		if ComposeVersion(value) {
			t.Fatal(value)
		}
	}
}
