package operator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

type upgradeImages struct{ drift bool }

func (i upgradeImages) Prove(_ context.Context, target, component, arch string) (release.ImageProof, error) {
	digest := strings.Repeat(target[:1], 64)
	if i.drift {
		digest = strings.Repeat("f", 64)
	}
	return release.ImageProof{Image: "ghcr.io/wongyiuming/frontiercloud-gin-" + component + "@sha256:" + digest, Revision: target, Platform: "linux/" + arch, Generation: migrations.Generation}, nil
}

type upgradeRunner struct {
	*fakeRunner
	data, secrets, fail string
	stopped             bool
	node                string
	generation          int
	role                string
	relations           []NodeFact
	onFact              func()
}

func (r *upgradeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if r.fail != "" && strings.Contains(call, r.fail) {
		return nil, errors.New("secret-fixture-not-for-output")
	}
	if strings.Contains(call, "context inspect") {
		return []byte(`"unix:///var/run/docker.sock"`), nil
	}
	if strings.Contains(call, "info --format {{.Architecture}}") {
		return []byte("x86_64"), nil
	}
	if strings.Contains(call, "volume inspect") {
		return json.Marshal(r.secrets)
	}
	if strings.Contains(call, "operator-status") {
		if r.onFact != nil {
			r.onFact()
		}
		_, e := os.Stat(filepath.Join(r.data, maintenance.Marker))
		role := r.role
		if role == "" {
			role = "Standalone"
		}
		generation := r.generation
		if generation == 0 {
			generation = migrations.Generation
		}
		return json.Marshal(RuntimeFact{NodeID: r.node, Role: role, NativeMaintenance: e == nil, Nodes: r.relations, Database: store.MaintenanceSnapshot{LogicalIdle: true, SchemaGeneration: generation}})
	}
	if strings.Contains(call, "prepare-release") {
		r.generation = migrations.Generation
	}
	if strings.Contains(call, "maintenance enter") || strings.Contains(call, "maintenance resume") {
		gate, e := maintenance.Open(r.data)
		if e != nil {
			return nil, e
		}
		defer gate.Close()
		if strings.Contains(call, "maintenance enter") {
			e = gate.Enter(ctx, func(context.Context) error { return nil })
		} else {
			e = gate.Resume(ctx, func(context.Context) error { return nil })
		}
		return []byte(`{}`), e
	}
	if strings.Contains(call, " stop ") {
		r.stopped = true
		return nil, nil
	}
	if strings.Contains(call, " up ") {
		r.stopped = false
		return nil, nil
	}
	if strings.Contains(call, "ps --all --format json") {
		state := "running"
		if r.stopped {
			state = "exited"
		}
		return json.Marshal([]map[string]string{{"Service": "web", "State": state}})
	}
	return r.fakeRunner.Run(ctx, name, args...)
}
func upgradeFixture(t *testing.T) (*Deployment, Receipt, *upgradeRunner, UpgradePlan) {
	t.Helper()
	d, base := fixture(t)
	base.config.Services["web"].Environment["DATA_ROOT"] = "/app/data"
	base.config.Services["web"].Environment["SQLITE_PATH"] = "/app/data/frontiercloud.db"
	base.config.Services["web"].Environment["SECRETS_DIR"] = "/run/frontiercloud-secrets"
	web := base.config.Services["web"]
	web.Volumes = append(web.Volumes, Mount{Type: "volume", Source: "runtime_secrets", Target: "/run/frontiercloud-secrets"})
	base.config.Services["web"] = web
	r, e := d.Install(context.Background(), strings.Repeat("a", 40), "amd64", fakeEvidence{true}, upgradeImages{})
	if e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(d.Directory, "data")
	secrets := filepath.Join(d.Directory, "isolated-secrets")
	for _, directory := range []string{data, secrets, filepath.Join(data, "media", "music")} {
		if e = os.MkdirAll(directory, 0700); e != nil {
			t.Fatal(e)
		}
	}
	for path, content := range map[string]string{filepath.Join(secrets, "node-vault.key"): "isolated-key", filepath.Join(data, "frontiercloud.db"): "isolated-database-state", filepath.Join(data, "media", "music", "actual.mp3"): "ID3-actual-recovery-bytes", filepath.Join(d.Directory, "docker-compose.yaml"): "services: {}\n"} {
		if e = os.WriteFile(path, []byte(content), 0600); e != nil {
			t.Fatal(e)
		}
	}
	runner := &upgradeRunner{fakeRunner: base, data: data, secrets: secrets, node: strings.Repeat("d", 32)}
	key := base64.URLEncoding.EncodeToString(make([]byte, 32))
	if e = os.WriteFile(filepath.Join(secrets, "node-vault.key"), []byte(key), 0600); e != nil {
		t.Fatal(e)
	}
	v, e := vault.New(key)
	if e != nil {
		t.Fatal(e)
	}
	binding := expectedNativeBinding(base.config, r.Database)
	sealed, e := v.Seal("frontiercloud-native-runtime-v1\n" + binding + runner.node)
	if e != nil {
		t.Fatal(e)
	}
	for name, value := range map[string]string{".native-store": binding, ".native-runtime": sealed} {
		if e = os.WriteFile(filepath.Join(data, name), []byte(value), 0600); e != nil {
			t.Fatal(e)
		}
	}
	runner.calls = nil
	d.Runner = runner
	p, e := d.PlanUpgrade(context.Background(), r, strings.Repeat("b", 40), "amd64", fakeEvidence{true}, upgradeImages{})
	if e != nil {
		t.Fatal(e)
	}
	return d, r, runner, p
}

func TestUpgradePlanDoesNotWriteOrStartAnything(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	if p.SHA256 != p.digest() || p.From != r.Revision || p.Target == r.Revision {
		t.Fatal(p)
	}
	for _, call := range runner.calls {
		for _, forbidden := range []string{" pull ", " run ", " up ", " stop ", "maintenance enter"} {
			if strings.Contains(call, forbidden) {
				t.Fatal("plan mutated", call)
			}
		}
	}
	for _, file := range []string{UpgradeJournal, OperationLock} {
		if _, e := os.Lstat(filepath.Join(d.Directory, file)); !os.IsNotExist(e) {
			t.Fatal("plan created state", file, e)
		}
	}
	if _, e := d.PlanUpgrade(context.Background(), r, "latest", "amd64", fakeEvidence{true}, upgradeImages{}); e == nil {
		t.Fatal("implicit moving target accepted")
	}
}

func TestUpgradeApplyRechecksApprovalIdentityAndDigestBeforeFreeze(t *testing.T) {
	for _, kind := range []string{"approval", "identity", "drift", "existing-backup", "changed-mount"} {
		t.Run(kind, func(t *testing.T) {
			d, r, runner, p := upgradeFixture(t)
			runner.calls = nil
			approval, node := p.SHA256, p.NodeID
			images := upgradeImages{}
			output := filepath.Join(d.Directory, "recovery.tar")
			switch kind {
			case "approval":
				approval = "wrong"
			case "identity":
				node = "wrong"
			case "drift":
				images.drift = true
			case "existing-backup":
				if e := os.WriteFile(output, []byte("retain"), 0600); e != nil {
					t.Fatal(e)
				}
			case "changed-mount":
				runner.config.Services["web"].Environment["DATA_ROOT"] = "/other"
			}
			if _, e := d.ApplyUpgrade(context.Background(), r, p, approval, node, output, false, fakeEvidence{true}, images); e == nil {
				t.Fatal("invalid apply admitted")
			}
			for _, call := range runner.calls {
				if strings.Contains(call, "maintenance enter") || strings.Contains(call, " stop ") || strings.Contains(call, "prepare-release") {
					t.Fatal("mutated before admission", call)
				}
			}
			if _, e := os.Lstat(filepath.Join(runner.data, maintenance.Marker)); !os.IsNotExist(e) {
				t.Fatal("source was fenced", e)
			}
		})
	}
}

func TestUpgradeUsesRealRecoveryBytesBeforeTargetAndExplicitOpen(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	ctx := context.Background()
	output := filepath.Join(d.Directory, "recovery.tar")
	state, e := d.ApplyUpgrade(ctx, r, p, p.SHA256, p.NodeID, output, false, fakeEvidence{true}, upgradeImages{})
	if e != nil {
		t.Fatal(e)
	}
	if state.Phase != "prepared_fenced" || state.BackupSHA == "" || state.BusinessVerified || !runner.stopped {
		t.Fatal(state)
	}
	if scratch, e := filepath.Glob(filepath.Join(d.Directory, ".fc-backup-*")); e != nil || len(scratch) != 0 {
		t.Fatal("successful backup retained private scratch", scratch, e)
	}
	check, e := recovery.Check(ctx, output, state.BackupSHA)
	if e != nil {
		t.Fatal(e)
	}
	if check.Manifest.Revision != r.Revision || check.Manifest.NodeID != p.NodeID {
		t.Fatal(check.Manifest)
	}
	target := filepath.Join(d.Directory, "material")
	if _, e = recovery.Apply(ctx, output, target, state.BackupSHA, p.NodeID); e == nil {
		t.Fatal("upgrade state backup was treated as a complete media restore")
	}
	actual, e := os.ReadFile(filepath.Join(runner.data, "media", "music", "actual.mp3"))
	if e != nil || string(actual) != "ID3-actual-recovery-bytes" {
		t.Fatal("upgrade changed retained media bytes", e)
	}
	_, next, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	if next.Revision != p.Target || next.State != "upgrade_fenced" {
		t.Fatal(next)
	}
	if _, e = d.OpenUpgrade(ctx, next, "wrong", p.NodeID); e == nil {
		t.Fatal("opened without approval")
	}
	state, e = d.OpenUpgrade(ctx, next, p.SHA256, p.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	if state.Phase != "opened" || !state.BusinessVerified {
		t.Fatal(state)
	}
	_, next, e = Open(d.Directory)
	if e != nil || next.State != "ready" {
		t.Fatal(next, e)
	}
	for _, marker := range []string{maintenance.Marker, sitecontrol.Manual} {
		if _, e = os.Lstat(filepath.Join(runner.data, marker)); !os.IsNotExist(e) {
			t.Fatal(marker, e)
		}
	}
}

func TestUpgradeFailurePreservesBackupAndNativeFenceWithoutRollback(t *testing.T) {
	for _, failure := range []string{"prepare-release", "recovery-verify"} {
		t.Run(failure, func(t *testing.T) {
			d, r, runner, p := upgradeFixture(t)
			runner.fail = failure
			output := filepath.Join(d.Directory, "recovery.tar")
			state, e := d.ApplyUpgrade(context.Background(), r, p, p.SHA256, p.NodeID, output, false, fakeEvidence{true}, upgradeImages{})
			if e == nil || state.Phase != "failed_fenced" || strings.Contains(e.Error(), "secret-fixture") {
				t.Fatal(state, e)
			}
			if _, e = recovery.Check(context.Background(), output, state.BackupSHA); e != nil {
				t.Fatal("lost recovery point", e)
			}
			if _, e = os.Stat(filepath.Join(runner.data, maintenance.Marker)); e != nil {
				t.Fatal("failure reopened source", e)
			}
			_, next, e := Open(d.Directory)
			if e != nil || next.Revision != p.Target || next.State == "ready" {
				t.Fatal("pretended rollback/ready", next, e)
			}
			if _, e = d.OpenUpgrade(context.Background(), next, p.SHA256, p.NodeID); e == nil {
				t.Fatal("opened failed upgrade")
			}
			for _, call := range runner.calls {
				if strings.Contains(call, "maintenance resume") {
					t.Fatal("failure resumed", call)
				}
			}
		})
	}
}

func TestUpgradeOpenPreservesAdministratorMaintenanceAndRefencesReadFailure(t *testing.T) {
	for _, kind := range []string{"prior-maintenance", "read-failure"} {
		t.Run(kind, func(t *testing.T) {
			d, r, runner, p := upgradeFixture(t)
			ctx := context.Background()
			if _, e := d.ApplyUpgrade(ctx, r, p, p.SHA256, p.NodeID, filepath.Join(d.Directory, "recovery.tar"), false, fakeEvidence{true}, upgradeImages{}); e != nil {
				t.Fatal(e)
			}
			_, next, e := Open(d.Directory)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "prior-maintenance" {
				if e = os.WriteFile(filepath.Join(runner.data, sitecontrol.Manual), []byte("manual\n"), 0600); e != nil {
					t.Fatal(e)
				}
			} else {
				runner.fail = "recovery-verify"
			}
			if _, e = d.OpenUpgrade(ctx, next, p.SHA256, p.NodeID); e == nil {
				t.Fatal("opened unsafe target")
			}
			if _, e = os.Stat(filepath.Join(runner.data, maintenance.Marker)); e != nil {
				t.Fatal("native fence lost", e)
			}
			if raw, e := os.ReadFile(filepath.Join(runner.data, sitecontrol.Manual)); e != nil || string(raw) != "manual\n" {
				t.Fatal("manual fence lost", e)
			}
		})
	}
}

func TestUpgradeOpenRechecksRecoveryMaterialAndPreparedIdentity(t *testing.T) {
	for _, kind := range []string{"missing-backup", "corrupt-backup", "changed-identity"} {
		t.Run(kind, func(t *testing.T) {
			d, r, runner, p := upgradeFixture(t)
			ctx := context.Background()
			output := filepath.Join(d.Directory, "recovery.tar")
			if _, e := d.ApplyUpgrade(ctx, r, p, p.SHA256, p.NodeID, output, false, fakeEvidence{true}, upgradeImages{}); e != nil {
				t.Fatal(e)
			}
			_, next, e := Open(d.Directory)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "missing-backup":
				if e = os.Remove(output); e != nil {
					t.Fatal(e)
				}
			case "corrupt-backup":
				if e = os.WriteFile(output, []byte("corrupted isolated archive"), 0600); e != nil {
					t.Fatal(e)
				}
			case "changed-identity":
				runner.node = strings.Repeat("e", 32)
			}
			runner.calls = nil
			if _, e = d.OpenUpgrade(ctx, next, p.SHA256, p.NodeID); e == nil {
				t.Fatal("changed recovery or identity opened")
			}
			for _, call := range runner.calls {
				if strings.Contains(call, "maintenance resume") || strings.Contains(call, " up ") {
					t.Fatal("resumed before renewed proof", call)
				}
			}
			if _, e = os.Stat(filepath.Join(runner.data, maintenance.Marker)); e != nil {
				t.Fatal("lost offline fence", e)
			}
		})
	}
}

func TestUpgradeGeneration6RecoveryPointIsNotRelabelledAsTargetGeneration7(t *testing.T) {
	if migrations.Generation != 7 {
		t.Skip("explicit generation-7 transition")
	}
	d, r, runner, _ := upgradeFixture(t)
	runner.generation = 6
	for key, proof := range r.Images {
		proof.Generation = 6
		r.Images[key] = proof
	}
	if e := replaceJSON(filepath.Join(d.Directory, ReceiptFile), r); e != nil {
		t.Fatal(e)
	}
	p, e := d.PlanUpgrade(context.Background(), r, strings.Repeat("b", 40), "amd64", fakeEvidence{true}, upgradeImages{})
	if e != nil {
		t.Fatal(e)
	}
	if p.FromGeneration != 6 || p.Generation != 7 {
		t.Fatal(p)
	}
	output := filepath.Join(d.Directory, "generation-6-recovery.tar")
	state, e := d.ApplyUpgrade(context.Background(), r, p, p.SHA256, p.NodeID, output, false, fakeEvidence{true}, upgradeImages{})
	if e != nil {
		t.Fatal(e)
	}
	runtimeSnapshot, e := recovery.Check(context.Background(), output, state.BackupSHA)
	if e != nil || runtimeSnapshot.Manifest.SchemaGeneration != 6 || state.Phase != "prepared_fenced" {
		t.Fatal(runtimeSnapshot.Manifest.SchemaGeneration, state.Phase, e)
	}
	confirmed := false
	for _, call := range runner.calls {
		if strings.Contains(call, "prepare-release") {
			if !strings.Contains(call, "--from-generation 6") || !strings.Contains(call, "--confirm-generation 7") || !strings.Contains(call, "--confirm-node-id "+p.NodeID) || !strings.Contains(call, "--backup-sha256 "+state.BackupSHA) {
				t.Fatal("schema migration omitted exact source/recovery confirmation", call)
			}
			confirmed = true
		}
	}
	if !confirmed {
		t.Fatal("forward DDL was never invoked")
	}
}
