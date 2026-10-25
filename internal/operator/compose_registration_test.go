package operator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

type registrationRunner struct {
	*upgradeRunner
	root             string
	wrongImage       bool
	withoutInstaller bool
	labels           map[string]string
	duplicateWeb     bool
	missingWeb       bool
}

func (r *registrationRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	if strings.Contains(call, "ps --all --format json") {
		var rows []registrationContainer
		for service := range r.config.Services {
			if service == "foc-host-init" && r.withoutInstaller || service == "web" && r.missingWeb {
				continue
			}
			row := registrationContainer{ID: service, Service: service, State: "running", Health: "healthy"}
			if service == "foc-host-init" {
				row.State = "exited"
				row.Health = ""
			}
			rows = append(rows, row)
			if service == "web" && r.duplicateWeb {
				rows = append(rows, row)
			}
		}
		r.calls = append(r.calls, call)
		return json.Marshal(rows)
	}
	if strings.Contains(call, "inspect --format {{json .Image}}") {
		id := "c"
		if args[len(args)-1] == "nginx" {
			id = "d"
		}
		if args[len(args)-1] == "redis" || r.wrongImage {
			id = "e"
		}
		r.calls = append(r.calls, call)
		return json.Marshal("sha256:" + strings.Repeat(id, 64))
	}
	if strings.Contains(call, "inspect --format {{json .Config.Labels}} web") {
		r.calls = append(r.calls, call)
		labels := map[string]string{"frontiercloud.runtime": "go", "frontiercloud.component": "web", "com.docker.compose.service": "web", "com.docker.compose.oneoff": "False", "com.docker.compose.project": r.config.Name, "com.docker.compose.project.working_dir": r.root, "com.docker.compose.project.config_files": filepath.Join(r.root, "docker-compose.yaml")}
		for name, value := range r.labels {
			labels[name] = value
		}
		return json.Marshal(labels)
	}
	if strings.Contains(call, "image inspect --format {{json .Config.Labels}}") {
		r.calls = append(r.calls, call)
		return json.Marshal(map[string]string{"frontiercloud.revision": strings.Repeat("a", 40)})
	}
	return r.upgradeRunner.Run(ctx, name, args...)
}

type registrationImages struct{}

func (registrationImages) Prove(_ context.Context, revision, component, arch string) (release.ImageProof, error) {
	id := "c"
	if component == "nginx" {
		id = "d"
	}
	repository, _ := release.ImageRepository(component)
	return release.ImageProof{Image: repository + "@sha256:" + strings.Repeat(id, 64), ConfigDigest: "sha256:" + strings.Repeat(id, 64), Revision: revision, Platform: "linux/" + arch, Generation: migrations.Generation}, nil
}

func registrationFixture(t *testing.T) (*Deployment, *registrationRunner) {
	d, base := fixture(t)
	var service Service
	raw := `{"image":"ghcr.io/wongyiuming/frontiercloud-gin-web:latest","user":"0:0","entrypoint":["/bin/sh","/app/operator/install-foc.sh"],"command":["auto"],"cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],"network_mode":"none","read_only":true,"environment":{"FOC_COMPOSE_INSTALL":"1","FOC_AUTOMATIC_PROJECT":"1"},"volumes":[{"type":"bind","source":"/usr","target":"/host/usr","read_only":true},{"type":"bind","source":"/etc","target":"/host/etc","read_only":true},{"type":"bind","source":"/usr/local/bin","target":"/usr/local/bin"},{"type":"bind","source":"/usr/local/lib/frontiercloud","target":"/usr/local/lib/frontiercloud"},{"type":"bind","source":"/etc/frontiercloud","target":"/etc/frontiercloud"}]}`
	if e := json.Unmarshal([]byte(raw), &service); e != nil {
		t.Fatal(e)
	}
	service.Image = "ghcr.io/wongyiuming/frontiercloud-gin-web@sha256:" + strings.Repeat("c", 64)
	service.Environment["FOC_OPERATOR_REVISION"] = strings.Repeat("a", 40)
	base.config.Services["foc-host-init"] = service
	base.config.Services["web"].Environment["DATA_ROOT"] = "/app/data"
	if e := os.Mkdir(filepath.Join(d.Directory, "data"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(d.Directory, "data", "frontiercloud.db"), []byte("unchanged-native-state"), 0600); e != nil {
		t.Fatal(e)
	}
	runner := &registrationRunner{upgradeRunner: &upgradeRunner{fakeRunner: base, data: filepath.Join(d.Directory, "data"), node: strings.Repeat("d", 32)}, root: d.Directory}
	d.Runner = runner
	return d, runner
}

func TestComposeRegistrationDoesNotDependOnInstallerContainer(t *testing.T) {
	for _, kind := range []string{"no-installer-service", "removed-installer-container"} {
		t.Run(kind, func(t *testing.T) {
			d, runner := registrationFixture(t)
			if kind == "no-installer-service" {
				delete(runner.config.Services, "foc-host-init")
			} else {
				runner.withoutInstaller = true
			}
			r, err := d.RegisterCompose(context.Background(), "amd64", fakeEvidence{true}, registrationImages{})
			if err != nil || r.State != "ready" {
				t.Fatal(r, err)
			}
			_, installed := r.ServiceImages["foc-host-init"]
			if installed != (kind == "removed-installer-container") {
				t.Fatal("registration invented or lost installer selection", r.ServiceImages)
			}
			if _, err = d.ValidateReceipt(context.Background(), r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInstallerFreeComposeRegistrationStillRequiresUniqueNativeWeb(t *testing.T) {
	cases := map[string]map[string]string{
		"different-project":   {"com.docker.compose.project": "other"},
		"different-directory": {"com.docker.compose.project.working_dir": "/unrelated"},
		"different-files":     {"com.docker.compose.project.config_files": "/unrelated/docker-compose.yaml"},
		"one-off":             {"com.docker.compose.oneoff": "True"},
		"forged-service":      {"com.docker.compose.service": "redis"},
		"foreign-runtime":     {"frontiercloud.runtime": "python"},
		"foreign-component":   {"frontiercloud.component": "nginx"},
		"scaled-web":          nil, "missing-web": nil, "unreviewed-image": nil, "image-drift": nil,
	}
	for name, labels := range cases {
		t.Run(name, func(t *testing.T) {
			d, runner := registrationFixture(t)
			delete(runner.config.Services, "foc-host-init")
			runner.labels, runner.duplicateWeb, runner.missingWeb, runner.wrongImage = labels, name == "scaled-web", name == "missing-web", name == "image-drift"
			if _, err := d.RegisterCompose(context.Background(), "amd64", fakeEvidence{name != "unreviewed-image"}, registrationImages{}); err == nil {
				t.Fatal("unsafe installer-free registration admitted")
			}
			if _, err := os.Lstat(filepath.Join(d.Directory, ReceiptFile)); !os.IsNotExist(err) {
				t.Fatal("rejected registration published a receipt", err)
			}
		})
	}
}

func TestRemovedInstallerStillRequiresIndependentReviewedPin(t *testing.T) {
	for _, kind := range []string{"invalid-revision", "different-pin"} {
		t.Run(kind, func(t *testing.T) {
			d, runner := registrationFixture(t)
			runner.withoutInstaller = true
			s := runner.config.Services["foc-host-init"]
			if kind == "invalid-revision" {
				s.Environment["FOC_OPERATOR_REVISION"] = "latest"
			} else {
				s.Image = "ghcr.io/wongyiuming/frontiercloud-gin-web@sha256:" + strings.Repeat("e", 64)
			}
			runner.config.Services["foc-host-init"] = s
			if _, err := d.RegisterCompose(context.Background(), "amd64", fakeEvidence{true}, registrationImages{}); err == nil {
				t.Fatal("unverified removed installer bundle admitted")
			}
		})
	}
}

func TestComposeRegistrationPinsActualImagesWithoutChangingBusinessState(t *testing.T) {
	d, runner := registrationFixture(t)
	r, e := d.RegisterCompose(context.Background(), "amd64", fakeEvidence{true}, registrationImages{})
	if e != nil || r.State != "ready" || r.Revision != strings.Repeat("a", 40) {
		t.Fatal(r, e)
	}
	opened, current, e := Open(d.Directory)
	if e != nil || opened.Project != r.Project {
		t.Fatal("project discovery did not survive reopen", e)
	}
	opened.Runner = runner
	if _, e = opened.ValidateReceipt(context.Background(), current); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(filepath.Join(d.Directory, "data", "frontiercloud.db"))
	if e != nil || string(data) != "unchanged-native-state" {
		t.Fatal("registration changed database", e)
	}
	for _, call := range runner.calls {
		for _, bad := range []string{" pull ", " run ", " up ", " stop ", "maintenance enter"} {
			if strings.Contains(call, bad) {
				t.Fatal("registration changed runtime", call)
			}
		}
	}
	if e = os.Remove(filepath.Join(d.Directory, ReceiptFile)); e != nil {
		t.Fatal(e)
	}
	retried, e := d.RegisterCompose(context.Background(), "amd64", fakeEvidence{true}, registrationImages{})
	if e != nil || retried.CreatedAt != r.CreatedAt {
		t.Fatal("interrupted metadata registration was not retryable", e)
	}
}

func TestComposeRegistrationRefusesUnreviewedOrDifferentRuntimeImages(t *testing.T) {
	for _, kind := range []string{"unreviewed", "image-drift", "installer-mount"} {
		t.Run(kind, func(t *testing.T) {
			d, runner := registrationFixture(t)
			runner.wrongImage = kind == "image-drift"
			if kind == "installer-mount" {
				s := runner.config.Services["foc-host-init"]
				s.Volumes = append(s.Volumes, Mount{Type: "bind", Source: "/business", Target: "/business"})
				runner.config.Services["foc-host-init"] = s
			}
			if _, e := d.RegisterCompose(context.Background(), "amd64", fakeEvidence{kind != "unreviewed"}, registrationImages{}); e == nil {
				t.Fatal("unsafe registration admitted")
			}
			if _, e := os.Lstat(filepath.Join(d.Directory, ReceiptFile)); !os.IsNotExist(e) {
				t.Fatal("rejected registration published receipt", e)
			}
		})
	}
}
