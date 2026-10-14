package operator

// Opt-in isolated development node. Publication proof is injected only here;
// default Compose initialization, host installation and Docker are actual.
import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

type composeRegistrationSpec struct {
	Directory     string            `json:"directory"`
	Role          string            `json:"role"`
	Database      string            `json:"database"`
	ConfigDigests map[string]string `json:"config_digests"`
}

type rawComposeRegistrationRunner struct{ directory string }

func (r rawComposeRegistrationRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name != "docker" {
		return nil, errors.New("isolated registration permits Docker only")
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = r.directory
	raw, e := cmd.Output()
	if e != nil {
		return nil, errors.New("isolated Docker registration command failed; output suppressed")
	}
	return raw, nil
}

type privateRegistrationImages struct{ digests map[string]string }

func (i privateRegistrationImages) Prove(_ context.Context, target, component, arch string) (release.ImageProof, error) {
	repository, e := release.ImageRepository(component)
	if e != nil {
		return release.ImageProof{}, e
	}
	return release.ImageProof{Image: repository + "@sha256:" + strings.Repeat("a", 64), ConfigDigest: i.digests[component], Revision: target, Platform: "linux/" + arch, Generation: migrations.Generation}, nil
}

func TestNativeDefaultComposeRegistersGlobalFoc(t *testing.T) {
	input := os.Getenv("FC_COMPOSE_REGISTRATION_SPEC")
	if input == "" {
		t.Skip("isolated development node only")
	}
	raw, e := os.ReadFile(input)
	if e != nil {
		t.Fatal(e)
	}
	var spec composeRegistrationSpec
	if e = json.Unmarshal(raw, &spec); e != nil {
		t.Fatal(e)
	}
	d, e := New(spec.Directory, spec.Role, spec.Database)
	if e != nil {
		t.Fatal(e)
	}
	d.Runner = rawComposeRegistrationRunner{spec.Directory}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	r, e := d.RegisterCompose(ctx, "amd64", fakeEvidence{true}, privateRegistrationImages{spec.ConfigDigests})
	if e != nil {
		t.Fatal("actual Compose registration", e)
	}
	// Only this fixture translates injected manifests to the actual local IDs.
	for name, image := range r.ServiceImages {
		if name == "nginx" {
			image = spec.ConfigDigests["nginx"]
		} else if strings.HasPrefix(image, "ghcr.io/wongyiuming/frontiercloud-gin-web@") {
			image = spec.ConfigDigests["web"]
		}
		r.ServiceImages[name] = image
	}
	lock := map[string]map[string]string{}
	for name, image := range r.ServiceImages {
		lock[name] = map[string]string{"image": image}
	}
	if e = replaceJSON(filepath.Join(spec.Directory, ImagesFile), map[string]any{"services": lock}); e != nil {
		t.Fatal(e)
	}
	if e = replaceJSON(filepath.Join(spec.Directory, ReceiptFile), r); e != nil {
		t.Fatal(e)
	}
	if _, e = d.ValidateReceipt(ctx, r); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat("/usr/local/bin/foc"); e != nil {
		t.Fatal("normal Compose did not install host command", e)
	}
	if e = exclusiveJSON(filepath.Join(spec.Directory, "compose-foc-evidence.json"), map[string]any{"status": "passed", "default_compose_installed_global_foc": true, "registration_executed": true, "public_installation_proof": false, "publication_proof_injected": true, "schema_generation": r.Images["web"].Generation, "role": spec.Role}); e != nil {
		t.Fatal(e)
	}
}
