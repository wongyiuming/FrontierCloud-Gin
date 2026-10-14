package operator

// Development-host only. The explicitly supplied JSON names an isolated
// Compose fixture created by tests/operator_recovery_acceptance.py. Publication
// proof is injected: this never claims an unreleased local image is public.
import (
	"context"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type composeUpgradeSpec struct {
	Directory                string `json:"directory"`
	Web                      string `json:"web_image_id"`
	TargetWeb                string `json:"target_web_image_id"`
	Edge                     string `json:"edge_image_id"`
	FailPrepare              bool   `json:"fail_prepare"`
	RecoverFailure           bool   `json:"recover_failure"`
	ExpectedSourceGeneration int    `json:"expected_source_generation,omitempty"`
}
type nativeUpgradeRunner struct {
	directory   string
	images      map[string]string
	override    map[string]map[string]any
	failPrepare bool
}

func (r *nativeUpgradeRunner) arguments(args []string) ([]string, error) {
	if len(args) > 1 && args[0] == "pull" {
		actual, ok := r.images[args[1]]
		if !ok {
			return nil, errors.New("unknown synthetic publication digest")
		}
		return []string{"image", "inspect", actual}, nil
	}
	if len(args) == 0 || args[0] != "compose" {
		return args, nil
	}
	command := -1
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--project-directory", "--project-name", "-f":
			i++
		default:
			command = i
		}
		if command >= 0 {
			break
		}
	}
	if command < 0 {
		return nil, errors.New("missing fixture Compose action")
	}
	if args[command] == "config" {
		return args, nil
	}
	if r.failPrepare && strings.Contains(strings.Join(args, " "), "prepare-release") {
		return nil, errors.New("injected target preparation failure at the native offline boundary")
	}
	raw, e := os.ReadFile(filepath.Join(r.directory, ImagesFile))
	if e != nil {
		return nil, e
	}
	var lock struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if e = json.Unmarshal(raw, &lock); e != nil {
		return nil, e
	}
	services := map[string]map[string]any{}
	for name, value := range lock.Services {
		override := map[string]any{}
		for key, item := range r.override[name] {
			override[key] = item
		}
		image := value.Image
		if actual, ok := r.images[image]; ok {
			image = actual
		}
		override["image"] = image
		services[name] = override
	}
	overlay := filepath.Join(r.directory, ".fc-test-upgrade-images.json")
	raw, e = json.Marshal(map[string]any{"services": services})
	if e != nil {
		return nil, e
	}
	if e = os.WriteFile(overlay, raw, 0600); e != nil {
		return nil, e
	}
	result := append([]string{}, args[:command]...)
	result = append(result, "-f", overlay)
	return append(result, args[command:]...), nil
}
func (r *nativeUpgradeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name != "docker" {
		return nil, errors.New("fixture only runs Docker")
	}
	args, e := r.arguments(args)
	if e != nil {
		return nil, e
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = r.directory
	raw, e := cmd.Output()
	if e != nil {
		return nil, errors.New("isolated Docker operation failed; secret-bearing output suppressed")
	}
	return raw, nil
}
func (r *nativeUpgradeRunner) RunTo(ctx context.Context, out io.Writer, name string, args ...string) error {
	if name != "docker" {
		return errors.New("fixture only streams Docker")
	}
	args, e := r.arguments(args)
	if e != nil {
		return e
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = r.directory
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return errors.New("isolated Docker dump failed; output suppressed")
	}
	return nil
}

func (r *nativeUpgradeRunner) RunFrom(ctx context.Context, in io.Reader, name string, args ...string) error {
	if name != "docker" {
		return errors.New("fixture only accepts Docker input")
	}
	args, e := r.arguments(args)
	if e != nil {
		return e
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = r.directory
	cmd.Stdin = in
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return errors.New("isolated MySQL restoration failed; output suppressed")
	}
	return nil
}

func TestOperatorUpgradeComposeAcceptance(t *testing.T) {
	input := os.Getenv("FRONTIERCLOUD_TEST_OPERATOR_UPGRADE")
	if input == "" {
		t.Skip("requires an explicit isolated native Compose fixture")
	}
	raw, e := os.ReadFile(input)
	if e != nil {
		t.Fatal(e)
	}
	var spec composeUpgradeSpec
	if json.Unmarshal(raw, &spec) != nil {
		t.Fatal("invalid fixture specification")
	}
	if !strings.HasPrefix(filepath.Base(spec.Directory), "fc-ops-recovery-") || spec.Web == "" || spec.Edge == "" || spec.TargetWeb == "" || spec.Web == spec.TargetWeb {
		t.Fatal("isolated fixture and distinct actual source/target images required")
	}
	d, r, e := Open(spec.Directory)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(r.Project, "fc-ops-recovery-") {
		t.Fatal("project is not this test's fixture")
	}
	raw, e = os.ReadFile(filepath.Join(spec.Directory, ImagesFile))
	if e != nil {
		t.Fatal(e)
	}
	var override struct {
		Services map[string]map[string]any `json:"services"`
	}
	if json.Unmarshal(raw, &override) != nil {
		t.Fatal("invalid fixture image lock")
	}
	runner := &nativeUpgradeRunner{directory: spec.Directory, images: map[string]string{}, override: override.Services, failPrepare: spec.FailPrepare}
	d.Runner = runner
	r.Revision = strings.Repeat("a", 40)
	r.SourceSHA = strings.Repeat("d", 40)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	for name, image := range r.ServiceImages {
		component := ""
		if image == spec.Web {
			component = "web"
		} else if image == spec.Edge {
			component = "nginx"
		}
		if component == "" {
			// The isolated fixture pins infrastructure by local image ID too.
			// Resume validates/pulls every recorded pin, including unchanged ones.
			runner.images[image] = image
			continue
		}
		for _, target := range []string{strings.Repeat("a", 40), strings.Repeat("b", 40)} {
			p, _ := (upgradeImages{}).Prove(ctx, target, component, "amd64")
			actual := image
			if component == "web" && target[0] == 'b' {
				actual = spec.TargetWeb
			}
			runner.images[p.Image] = actual
			if target[0] == 'a' {
				r.ServiceImages[name] = p.Image
			}
		}
	}
	locked := map[string]map[string]string{}
	for name, image := range r.ServiceImages {
		locked[name] = map[string]string{"image": image}
	}
	if e = replaceJSON(filepath.Join(spec.Directory, ImagesFile), map[string]any{"services": locked}); e != nil {
		t.Fatal(e)
	}
	if e = replaceJSON(filepath.Join(spec.Directory, ReceiptFile), r); e != nil {
		t.Fatal(e)
	}
	archRaw, e := runner.Run(ctx, "docker", "info", "--format", "{{.Architecture}}")
	if e != nil {
		t.Fatal(e)
	}
	p, e := d.PlanUpgrade(ctx, r, strings.Repeat("b", 40), Architecture(string(archRaw)), fakeEvidence{true}, upgradeImages{})
	if e != nil {
		t.Fatal(e)
	}
	if spec.ExpectedSourceGeneration != 0 && p.FromGeneration != spec.ExpectedSourceGeneration {
		t.Fatal("source runtime schema differs from explicitly requested acceptance generation")
	}
	state, e := d.ApplyUpgrade(ctx, r, p, p.SHA256, p.NodeID, filepath.Join(spec.Directory, "pre-upgrade-recovery.tar"), true, fakeEvidence{true}, upgradeImages{})
	if state.BackupSHA != "" {
		checked, err := recovery.Check(ctx, filepath.Join(spec.Directory, "pre-upgrade-recovery.tar"), state.BackupSHA)
		if err != nil || checked.Manifest.Scope != recovery.UpgradeStateScope || checked.Manifest.CompleteCluster {
			t.Fatal("upgrade backup scope mismatch", err)
		}
		for _, entry := range checked.Manifest.Files {
			if strings.HasPrefix(entry.Path, "data/media/") || strings.HasPrefix(entry.Path, "data/lyrics/") || strings.HasPrefix(entry.Path, "data/recordings/") {
				t.Fatal("business file entered upgrade archive", entry.Path)
			}
		}
	}
	if spec.FailPrepare {
		if e == nil || state.Phase != "failed_fenced" || state.BackupSHA == "" {
			t.Fatal("target failure did not retain a verified fenced recovery point", e)
		}
		if spec.RecoverFailure {
			cfg, err := d.Config(ctx, true)
			if err != nil {
				t.Fatal(err)
			}
			if r.Database == "sqlite" {
				data, err := upgradeDataRoot(cfg)
				if err != nil {
					t.Fatal(err)
				}
				database := strings.TrimPrefix(cfg.Services["web"].Environment["SQLITE_PATH"], cfg.Services["web"].Environment["DATA_ROOT"]+"/")
				cmd := exec.CommandContext(ctx, "python3", "-c", `import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('CREATE TABLE foc_failed_schema_probe(value TEXT)'); c.execute("INSERT INTO foc_failed_schema_probe VALUES ('failed-state')"); c.commit(); c.close()`, filepath.Join(data, database))
				if err = cmd.Run(); err != nil {
					t.Fatal("isolated failed SQLite DDL injection", err)
				}
			} else {
				if _, err := runner.Run(ctx, "docker", append(d.composeArgs(true), "exec", "-T", "mysql", "sh", "-c", `MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) exec mysql -u root "$MYSQL_DATABASE" -e "CREATE TABLE foc_failed_schema_probe(value TEXT); INSERT INTO foc_failed_schema_probe VALUES ('failed-state');"`)...); err != nil {
					t.Fatal("isolated failed MySQL DDL injection", err)
				}
			}
			_, current, err := Open(spec.Directory)
			if err != nil {
				t.Fatal(err)
			}
			material := filepath.Join(filepath.Dir(spec.Directory), "state-recovery-"+filepath.Base(spec.Directory))
			state, err = d.RecoverUpgradeState(ctx, current, p.SHA256, p.NodeID, state.BackupSHA, material, true)
			if err != nil || state.Phase != "prepared_fenced" || state.Plan.RecoveryOf != p.SHA256 {
				t.Fatal("native retained-mount state restoration", err)
			}
			if r.Database == "sqlite" {
				data, err := upgradeDataRoot(cfg)
				if err != nil {
					t.Fatal(err)
				}
				database := strings.TrimPrefix(cfg.Services["web"].Environment["SQLITE_PATH"], cfg.Services["web"].Environment["DATA_ROOT"]+"/")
				cmd := exec.CommandContext(ctx, "python3", "-c", `import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); assert not c.execute("SELECT name FROM sqlite_master WHERE name='foc_failed_schema_probe'").fetchall(); c.close(); c=sqlite3.connect(sys.argv[2]); assert c.execute('SELECT value FROM foc_failed_schema_probe').fetchone()[0]=='failed-state'; c.close()`, filepath.Join(data, database), filepath.Join(material, "failed", "data", database))
				if err = cmd.Run(); err != nil {
					t.Fatal("restored SQLite DDL or retained failed state differs", err)
				}
			} else {
				raw, err := runner.Run(ctx, "docker", append(d.composeArgs(true), "exec", "-T", "mysql", "sh", "-c", `MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) exec mysql -N -u root "$MYSQL_DATABASE" -e "SHOW TABLES LIKE 'foc_failed_schema_probe'"`)...)
				if err != nil || strings.TrimSpace(string(raw)) != "" {
					t.Fatal("failed MySQL DDL survived", err)
				}
				failed, err := os.ReadFile(filepath.Join(material, "failed-database.sql"))
				if err != nil || !strings.Contains(string(failed), "foc_failed_schema_probe") {
					t.Fatal("failed MySQL state discarded", err)
				}
			}
			_, current, err = Open(spec.Directory)
			if err != nil {
				t.Fatal(err)
			}
			state, err = d.OpenUpgrade(ctx, current, state.Plan.SHA256, p.NodeID)
			if err != nil || state.Phase != "opened" || !state.BusinessVerified {
				t.Fatal("native recovered source opening", err)
			}
			evidence := map[string]any{"phase": state.Phase, "actual_compose": true, "publication_proof_injected": true, "source_schema_generation": p.FromGeneration, "target_schema_generation": p.FromGeneration, "backup_sha256": state.BackupSHA, "backup_scope": recovery.UpgradeStateScope, "business_files_included": false, "native_managed_business_reads": true, "failed_ddl_restored": true, "failed_state_retained": true, "original_business_mounts_retained": true}
			if err = exclusiveJSON(filepath.Join(spec.Directory, "upgrade-evidence.json"), evidence); err != nil {
				t.Fatal(err)
			}
			return
		}
		if e = exclusiveJSON(filepath.Join(spec.Directory, "upgrade-evidence.json"), map[string]any{"phase": state.Phase, "actual_compose": true, "publication_proof_injected": true, "source_schema_generation": p.FromGeneration, "target_schema_generation": p.Generation, "target_failure_injected": true, "backup_sha256": state.BackupSHA, "backup_scope": recovery.UpgradeStateScope, "business_files_included": false, "no_automatic_rollback": true}); e != nil {
			t.Fatal(e)
		}
		return
	}
	if e != nil || state.Phase != "prepared_fenced" {
		t.Fatal("native prepare failed", e)
	}
	_, next, e := Open(spec.Directory)
	if e != nil {
		t.Fatal(e)
	}
	state, e = d.ResumeUpgrade(ctx, next, p.SHA256, p.NodeID, true, fakeEvidence{true}, upgradeImages{})
	if e != nil || state.Phase != "prepared_fenced" {
		t.Fatal("native interrupted preparation resume failed", e)
	}
	state, e = d.OpenUpgrade(ctx, next, p.SHA256, p.NodeID)
	if e != nil || state.Phase != "opened" || !state.BusinessVerified {
		t.Fatal("native activation failed", e)
	}
	_, next, e = Open(spec.Directory)
	if e != nil {
		t.Fatal(e)
	}
	// Restore concrete private-image receipts and the fixture-owned resource
	// overrides for the following unmodified CLI backup/restore acceptance.
	// Only this test maps publication proof to IDs; bind the effective private
	// configuration again rather than exempting its limits from production hashing.
	for name, image := range next.ServiceImages {
		if actual, ok := runner.images[image]; ok {
			image = actual
			next.ServiceImages[name] = actual
		}
		override.Services[name]["image"] = image
	}
	if e = replaceJSON(filepath.Join(spec.Directory, ImagesFile), override); e != nil {
		t.Fatal(e)
	}
	actualConfig, e := d.Config(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	next.SelectionHash = selectionHash(actualConfig)
	if e = replaceJSON(filepath.Join(spec.Directory, ReceiptFile), next); e != nil {
		t.Fatal(e)
	}
	if _, e = d.ValidateReceipt(ctx, next); e != nil {
		t.Fatal("concrete private-fixture handover did not retain binding", e)
	}
	if e = exclusiveJSON(filepath.Join(spec.Directory, "upgrade-evidence.json"), map[string]any{"phase": state.Phase, "actual_compose": true, "publication_proof_injected": true, "source_schema_generation": p.FromGeneration, "target_schema_generation": p.Generation, "source_web_image_id": spec.Web, "target_web_image_id": spec.TargetWeb, "backup_sha256": state.BackupSHA, "backup_scope": recovery.UpgradeStateScope, "business_files_included": false, "native_managed_business_reads": state.BusinessVerified, "native_prepared_upgrade_resume_verified": true}); e != nil {
		t.Fatal(e)
	}
}
