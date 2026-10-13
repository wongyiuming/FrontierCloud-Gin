package operator

// Private development acceptance of the real Install protocol. Publication
// evidence and image resolution are deliberately injected only in this test
// binary; Docker, Compose, native initialization, databases and TLS are real.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type installComposeSpec struct {
	Directory        string            `json:"directory"`
	Role             string            `json:"role"`
	Database         string            `json:"database"`
	Profile          string            `json:"profile"`
	Case             string            `json:"case"`
	Images           map[string]string `json:"images"`
	PullFailureImage string            `json:"pull_failure_image"`
}

type installComposeRunner struct {
	spec       installComposeSpec
	started    bool
	pulls      int
	ups        int
	pullFailed bool
}

func (r *installComposeRunner) raw(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = r.spec.Directory
	raw, e := cmd.Output()
	if e != nil {
		return nil, errors.New("isolated Docker command failed; secret-bearing output suppressed")
	}
	return raw, nil
}

func (r *installComposeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name != "docker" {
		return nil, errors.New("installation fixture only permits Docker")
	}
	for _, arg := range args {
		if arg == "build" {
			return nil, errors.New("installation attempted compilation")
		}
	}
	if len(args) > 1 && args[0] == "pull" {
		r.pulls++
		if r.spec.Case == "pull-failure" {
			_, e := r.raw(ctx, "pull", r.spec.PullFailureImage)
			r.pullFailed = e != nil
			if e == nil {
				return nil, errors.New("injected unavailable registry unexpectedly served an image")
			}
			return nil, e
		}
		image := args[1]
		if actual, ok := r.spec.Images[image]; ok {
			image = actual
		}
		// These images were built in an isolated builder before this test. The
		// installed host process needs only Docker and this compiled test binary.
		return r.raw(ctx, "image", "inspect", image)
	}
	if len(args) == 0 || args[0] != "compose" {
		return r.raw(ctx, args...)
	}
	action := -1
	for i := 1; i < len(args); i++ {
		if args[i] == "--project-directory" || args[i] == "--project-name" || args[i] == "-f" {
			i++
			continue
		}
		action = i
		break
	}
	if action < 0 {
		return nil, errors.New("missing Compose action")
	}
	if args[action] == "config" || args[action] == "ps" {
		return r.raw(ctx, args...)
	}
	actual := append([]string{}, args[:action]...)
	actual = append(actual, "-f", filepath.Join(r.spec.Directory, "private-runtime.yaml"))
	if args[action] == "up" {
		r.ups++
		if !r.started {
			r.started = true
			// Bootstrap only the private CA trust file before consumer creation,
			// matching the existing certificate-container fixture. No public CA
			// or host port is used. Native data remains freshly initialized.
			if _, e := r.raw(ctx, append(append([]string{}, actual...), "up", "-d", "--no-build", "--pull", "never", "certificate-agent")...); e != nil {
				return nil, e
			}
			deadline := time.Now().Add(60 * time.Second)
			for {
				if _, e := os.Stat(filepath.Join(r.spec.Directory, "control", "ca-ready")); e == nil {
					break
				}
				if time.Now().After(deadline) {
					return nil, errors.New("private CA startup timed out")
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(100 * time.Millisecond):
				}
			}
		}
	}
	actual = append(actual, args[action:]...)
	for i := range actual {
		if i > 0 && actual[i-1] == "--wait-timeout" {
			actual[i] = "75"
		}
	}
	return r.raw(ctx, actual...)
}

func TestOperatorInstallComposeAcceptance(t *testing.T) {
	input := os.Getenv("FRONTIERCLOUD_TEST_OPERATOR_INSTALL")
	if input == "" {
		t.Skip("requires explicit isolated native installation fixture")
	}
	raw, e := os.ReadFile(input)
	if e != nil {
		t.Fatal(e)
	}
	var spec installComposeSpec
	if json.Unmarshal(raw, &spec) != nil || !filepath.IsAbs(spec.Directory) || !strings.HasPrefix(filepath.Base(spec.Directory), "fc-ops-install-") {
		t.Fatal("invalid isolated installation fixture")
	}
	if spec.Role != "master" && spec.Role != "storage" {
		t.Fatal("invalid role")
	}
	d, e := New(spec.Directory, spec.Role, spec.Database)
	if e != nil {
		t.Fatal(e)
	}
	runner := &installComposeRunner{spec: spec}
	d.Runner = runner
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cfg, e := d.Config(ctx, false)
	if e != nil || !strings.HasPrefix(cfg.Name, "fc-ops-install-") {
		t.Fatal("non-fixture project", e)
	}
	dataDirectory := ""
	for _, mount := range cfg.Services["web"].Volumes {
		if mount.Type == "bind" && mount.Target == "/app/data" && !mount.ReadOnly {
			if dataDirectory != "" {
				t.Fatal("ambiguous native data mount")
			}
			dataDirectory = mount.Source
		}
	}
	if !filepath.IsAbs(dataDirectory) || !strings.HasPrefix(dataDirectory, spec.Directory+string(os.PathSeparator)) {
		t.Fatal("fixture data leaves its isolated directory")
	}
	if spec.Case == "pull-failure" && !strings.HasPrefix(spec.PullFailureImage, "127.0.0.1:") {
		t.Fatal("pull-failure must target an isolated loopback registry")
	}
	for _, name := range []string{"go", "node", "nodejs", "python", "python3", "gcc", "cc"} {
		if _, e := exec.LookPath(name); e == nil {
			t.Fatal("host compiler/interpreter remained in fixture PATH", name)
		}
	}
	arch, e := runner.raw(ctx, "info", "--format", "{{.Architecture}}")
	if e != nil {
		t.Fatal(e)
	}
	images := &fakeImages{}
	result := map[string]any{"actual_compose": true, "production_publication_verified": false, "publication_proof_injected": true, "image_resolution_injected": true, "host_compilers_on_path": false, "case": spec.Case, "profile": spec.Profile, "database": spec.Database}
	defer func() {
		if runner.started {
			stop, done := context.WithTimeout(context.Background(), 45*time.Second)
			defer done()
			if _, e := d.Compose(stop, true, "stop", "--timeout", "15"); e != nil {
				t.Error("could not stop owned installation fixture", e)
			}
		}
	}()
	r, e := d.Install(ctx, "", Architecture(string(arch)), fakeEvidence{true}, images)
	if spec.Case == "guard" {
		if e == nil || runner.pulls != 0 || runner.ups != 0 || len(images.calls) != 0 {
			t.Fatal("nonempty target reached initialization", e)
		}
		result["target_guard_refused_before_images"] = true
	} else if spec.Case == "pull-failure" {
		if e == nil || !runner.pullFailed || runner.ups != 0 {
			t.Fatal("actual failed pull initialized services", e)
		}
		if _, e := os.Stat(filepath.Join(spec.Directory, ReceiptFile)); !os.IsNotExist(e) {
			t.Fatal("failed pull wrote receipt")
		}
		result["actual_docker_pull_failed_before_initialization"] = true
	} else if spec.Case == "certificate-failure" {
		if e == nil || r.State != "prepared" {
			t.Fatal("failed certificate installation claimed ready", e)
		}
		_, saved, e := Open(spec.Directory)
		if e != nil || saved.State != "prepared" {
			t.Fatal("failed installation lost prepared receipt", e)
		}
		if _, e := os.Stat(filepath.Join(spec.Directory, "control", "ca-rejected")); e != nil {
			t.Fatal("CA rejection was not actually exercised")
		}
		before, e := os.ReadFile(filepath.Join(spec.Directory, ReceiptFile))
		if e != nil {
			t.Fatal(e)
		}
		vaultPath, e := installFixtureVaultPath(ctx, d, runner, cfg.Name)
		if e != nil {
			t.Fatal(e)
		}
		key, e := os.ReadFile(vaultPath)
		if e != nil || len(key) == 0 {
			t.Fatal("failed installation lost initialized vault material")
		}
		keyHash, pulls, ups := sha256.Sum256(key), runner.pulls, runner.ups
		if _, e := d.Install(ctx, "", Architecture(string(arch)), fakeEvidence{true}, images); e == nil {
			t.Fatal("failed nonempty installation was reinitialized")
		}
		key, e = os.ReadFile(vaultPath)
		if e != nil || sha256.Sum256(key) != keyHash || pulls != runner.pulls || ups != runner.ups {
			t.Fatal("retry changed failed installation material or started initialization")
		}
		after, e := os.ReadFile(filepath.Join(spec.Directory, ReceiptFile))
		if e != nil || string(before) != string(after) {
			t.Fatal("failed install receipt overwritten")
		}
		result["failed_prepared_receipt_retained"] = true
		result["actual_ca_rejection_verified"] = true
		result["failed_native_vault_key_preserved"] = true
	} else if spec.Case == "success" {
		if e != nil || r.State != "ready" {
			t.Fatal("fresh native installation failed", e)
		}
		// Compose health can turn green before the controller's bounded serving
		// observation loop publishes its marker. Wait for that independent proof.
		observed := time.Now().Add(20 * time.Second)
		for {
			if _, e := os.Stat(filepath.Join(spec.Directory, "control", "issued-and-serving")); e == nil {
				break
			}
			if time.Now().After(observed) {
				t.Fatal("fresh local-CA issuance and serving not observed")
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
		fact := func() RuntimeFact {
			t.Helper()
			v, e := d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "operator-status")
			if e != nil {
				t.Fatal(e)
			}
			var fact RuntimeFact
			if json.Unmarshal(v, &fact) != nil || len(fact.NodeID) != 32 {
				t.Fatal("native identity unavailable")
			}
			return fact
		}
		first := fact()
		cert, e := d.Compose(ctx, true, "exec", "-T", "certificate-agent", "/app/frontiercloud", "certificate-status")
		if e != nil {
			t.Fatal(e)
		}
		var certificate map[string]any
		if json.Unmarshal(cert, &certificate) != nil {
			t.Fatal("invalid native certificate observation")
		}
		prepared := r
		prepared.State = "prepared"
		if e := replaceJSON(filepath.Join(spec.Directory, ReceiptFile), prepared); e != nil {
			t.Fatal(e)
		}
		resumePulls := runner.pulls
		r, e = d.ResumeInstall(ctx, prepared)
		if e != nil || r.State != "ready" || runner.pulls != resumePulls || fact().NodeID != first.NodeID {
			t.Fatal("native prepared installation resume changed identity/pins or failed", e)
		}
		result["native_prepared_install_resume_verified"] = true
		beforeReceipt, e := os.ReadFile(filepath.Join(spec.Directory, ReceiptFile))
		if e != nil {
			t.Fatal(e)
		}
		webBefore, e := d.Compose(ctx, true, "ps", "--quiet", "web")
		if e != nil {
			t.Fatal(e)
		}
		vaultPath, e := installFixtureVaultPath(ctx, d, runner, cfg.Name)
		if e != nil {
			t.Fatal(e)
		}
		key, e := os.ReadFile(vaultPath)
		if e != nil {
			t.Fatal("native vault unavailable", e)
		}
		keyHash := sha256.Sum256(key)
		premasterPath := filepath.Join(dataDirectory, "media-keys", "media-premaster.key")
		premaster, e := os.ReadFile(premasterPath)
		if spec.Role == "master" && e != nil || spec.Role == "storage" && !os.IsNotExist(e) {
			t.Fatal("native premaster ownership differs from deployment role", e)
		}
		premasterHash := sha256.Sum256(premaster)
		imageBefore, e := runner.raw(ctx, "inspect", "--format", "{{.Image}}", strings.TrimSpace(string(webBefore)))
		if e != nil || strings.TrimSpace(string(imageBefore)) != spec.Images["ghcr.io/wongyiuming/frontiercloud-gin-web@sha256:"+strings.Repeat("c", 64)] {
			t.Fatal("running web does not match the private resolved image")
		}
		targets := []string{"web"}
		if spec.Role == "master" {
			targets = append(targets, "nginx")
		}
		args := append([]string{"up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "75", "--force-recreate", "--no-deps"}, targets...)
		if _, e := d.Compose(ctx, true, args...); e != nil {
			t.Fatal("installed services failed recreation", e)
		}
		webAfter, e := d.Compose(ctx, true, "ps", "--quiet", "web")
		if e != nil || string(webBefore) == string(webAfter) {
			t.Fatal("native web was not recreated")
		}
		imageAfter, e := runner.raw(ctx, "inspect", "--format", "{{.Image}}", strings.TrimSpace(string(webAfter)))
		if e != nil || string(imageBefore) != string(imageAfter) {
			t.Fatal("recreation changed the actual running image")
		}
		next := fact()
		if first.NodeID != next.NodeID || first.Database.SchemaGeneration != next.Database.SchemaGeneration {
			t.Fatal("recreation changed identity/database generation")
		}
		key, e = os.ReadFile(vaultPath)
		if e != nil || sha256.Sum256(key) != keyHash {
			t.Fatal("recreation changed native vault key")
		}
		premaster, e = os.ReadFile(premasterPath)
		if spec.Role == "master" && (e != nil || sha256.Sum256(premaster) != premasterHash) || spec.Role == "storage" && !os.IsNotExist(e) {
			t.Fatal("recreation changed native media-key ownership")
		}
		afterReceipt, e := os.ReadFile(filepath.Join(spec.Directory, ReceiptFile))
		if e != nil || string(beforeReceipt) != string(afterReceipt) {
			t.Fatal("recreation changed version receipt")
		}
		if _, e := d.ValidateReceipt(ctx, r); e != nil {
			t.Fatal(e)
		}
		result["fresh_local_ca_serving_verified"] = true
		result["native_node_id"] = first.NodeID
		result["native_role"] = first.Role
		result["schema_generation"] = first.Database.SchemaGeneration
		result["recreated_identity_key_and_revision_stable"] = true
		result["runtime_web_image_id"] = strings.TrimSpace(string(imageAfter))
		result["native_vault_key_preserved"] = true
		result["media_premaster_present"] = spec.Role == "master"
		h := sha256.Sum256(beforeReceipt)
		result["receipt_sha256"] = hex.EncodeToString(h[:])
		result["certificate"] = certificate
	} else {
		t.Fatal("unknown isolated installation case")
	}
	result["install_pull_calls"] = runner.pulls
	result["install_up_calls"] = runner.ups
	if e := exclusiveJSON(filepath.Join(spec.Directory, "install-evidence.json"), result); e != nil {
		t.Fatal(e)
	}
	t.Log("PASS: private native installation protocol", spec.Profile, spec.Database, spec.Case)
}

func installFixtureVaultPath(ctx context.Context, d *Deployment, runner *installComposeRunner, project string) (string, error) {
	web, e := d.Compose(ctx, true, "ps", "--all", "--quiet", "web")
	if e != nil || len(strings.Fields(string(web))) != 1 {
		return "", errors.New("actual native web container unavailable")
	}
	mountsRaw, e := runner.raw(ctx, "inspect", "--format", "{{json .Mounts}}", strings.TrimSpace(string(web)))
	var mounts []struct{ Source, Destination, Name string }
	if e != nil || json.Unmarshal(mountsRaw, &mounts) != nil {
		return "", errors.New("actual native mounts unavailable")
	}
	for _, mount := range mounts {
		if mount.Destination == "/run/frontiercloud-secrets" && strings.HasPrefix(mount.Name, project+"_") && filepath.IsAbs(mount.Source) {
			return filepath.Join(mount.Source, "node-vault.key"), nil
		}
	}
	return "", errors.New("actual private native vault mount unavailable")
}

// Keep the synthetic proof mapping explicit in this test; production image
// verifier never accepts these local image IDs as registry evidence.
var _ Images = (*fakeImages)(nil)
