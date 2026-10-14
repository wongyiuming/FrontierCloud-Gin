package operator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

const UpgradeJournal = ".fc-upgrade.json"
const upgradeManualStage = ".fc-upgrade-manual"

// A plan is public review material, not an authorization token. Apply requires
// its digest, the source NodeID, a new recovery output and fresh remote proof.
type UpgradePlan struct {
	Version        int                           `json:"version"`
	NodeID         string                        `json:"node_id"`
	Project        string                        `json:"project"`
	Role           string                        `json:"role"`
	Database       string                        `json:"database"`
	From           string                        `json:"from_revision"`
	Target         string                        `json:"target_revision"`
	SourceSHA      string                        `json:"reviewed_source_sha"`
	Architecture   string                        `json:"architecture"`
	Generation     int                           `json:"schema_generation"`
	FromGeneration int                           `json:"from_schema_generation"`
	ReceiptSHA     string                        `json:"receipt_sha256"`
	Images         map[string]release.ImageProof `json:"images"`
	ServiceImages  map[string]string             `json:"service_images"`
	CreatedAt      int64                         `json:"created_at"`
	ExpiresAt      int64                         `json:"expires_at"`
	SHA256         string                        `json:"plan_sha256"`
	RecoveryScope  string                        `json:"recovery_scope,omitempty"`
}

type UpgradeState struct {
	Version               int         `json:"version"`
	Phase                 string      `json:"phase"`
	Plan                  UpgradePlan `json:"plan"`
	Previous              Receipt     `json:"previous_receipt"`
	BackupFile            string      `json:"backup_file"`
	BackupSHA             string      `json:"backup_sha256,omitempty"`
	BackupCompleteCluster bool        `json:"backup_complete_cluster"`
	BackupCleanupWarning  string      `json:"backup_cleanup_warning,omitempty"`
	BackupScratch         string      `json:"backup_retained_scratch,omitempty"`
	ManualOwned           bool        `json:"owns_manual_maintenance"`
	ManualStaged          bool        `json:"manual_creation_staged,omitempty"`
	StageCleanupWarning   string      `json:"stage_cleanup_warning,omitempty"`
	Failure               string      `json:"failure,omitempty"`
	BusinessVerified      bool        `json:"business_verified"`
}

func upgradeHash(value any) string {
	raw, _ := json.Marshal(value)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func (p UpgradePlan) digest() string { p.SHA256 = ""; return upgradeHash(p) }

func ReadUpgradePlan(path string) (UpgradePlan, error) {
	var p UpgradePlan
	raw, e := readRegular(path, 1<<20)
	if e != nil {
		return p, e
	}
	if _, e = protocol.ParseStrictJSON(raw, 1<<20); e != nil {
		return p, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || !p.valid(time.Now()) {
		return p, errors.New("invalid or expired upgrade plan")
	}
	return p, nil
}
func (p UpgradePlan) valid(now time.Time) bool {
	return (p.RecoveryScope == "" || p.RecoveryScope == recovery.UpgradeStateScope) && p.Version == 1 && p.NodeID != "" && release.ValidSHA(p.From) && release.ValidSHA(p.Target) && p.Target != p.From && p.Generation == migrations.Generation && recovery.SupportedSchemaGeneration(p.FromGeneration) && p.CreatedAt <= now.Unix() && p.ExpiresAt > now.Unix() && p.ExpiresAt-p.CreatedAt == 3600 && p.SHA256 == p.digest()
}

func (d *Deployment) upgradeFact(ctx context.Context, r Receipt) (RuntimeFact, error) {
	var fact RuntimeFact
	raw, e := d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "operator-status")
	if e != nil || json.Unmarshal(raw, &fact) != nil || fact.NodeID == "" {
		return fact, errors.New("running deployment identity cannot be verified")
	}
	if fact.NativeMaintenance || fact.Maintenance || !fact.Database.LogicalIdle || !recovery.SupportedSchemaGeneration(fact.Database.SchemaGeneration) || r.Role == "storage" && fact.Role != "Follower" || r.Role == "master" && fact.Role != "Master" && fact.Role != "Standalone" {
		return fact, errors.New("upgrade requires a ready matching role/schema with no maintenance or unfinished resource transactions")
	}
	return fact, nil
}

func (d *Deployment) targetImages(ctx context.Context, r Receipt, target, arch string, evidence Evidence, images Images) (string, map[string]release.ImageProof, map[string]string, error) {
	proof, e := evidence.Artifact(ctx, target)
	if e != nil || proof["publishable"] != true || proof["sha"] != target || !release.ValidSHA(fmtString(proof["ci_sha"])) {
		return "", nil, nil, errors.New("target lacks reviewed main release and exact-source CI proof")
	}
	components := map[string]release.ImageProof{}
	services := map[string]string{}
	for name, old := range r.ServiceImages {
		component := ""
		for _, c := range []string{"web", "nginx"} {
			repo, _ := release.ImageRepository(c)
			if strings.HasPrefix(old, repo+"@sha256:") {
				component = c
				break
			}
		}
		if component == "" {
			services[name] = old
			continue
		}
		p, exists := components[component]
		if !exists {
			p, e = images.Prove(ctx, target, component, arch)
			if e != nil {
				return "", nil, nil, e
			}
			repo, _ := release.ImageRepository(component)
			if p.Revision != target || p.Generation != migrations.Generation || p.Platform != "linux/"+arch || !strings.HasPrefix(p.Image, repo+"@sha256:") {
				return "", nil, nil, release.ErrImageIntegrity
			}
			components[component] = p
		}
		services[name] = p.Image
	}
	if _, ok := components["web"]; !ok {
		return "", nil, nil, errors.New("recorded application image is not a public immutable release")
	}
	return fmtString(proof["ci_sha"]), components, services, nil
}
func fmtString(v any) string { s, _ := v.(string); return s }

// PlanUpgrade performs no pull, lock creation, container run, stop or mutation.
// It retains every Compose configuration and infrastructure image selection.
func (d *Deployment) PlanUpgrade(ctx context.Context, r Receipt, target, arch string, evidence Evidence, images Images) (UpgradePlan, error) {
	var p UpgradePlan
	if !release.ValidSHA(target) || target == r.Revision || r.State != "ready" || arch != "amd64" && arch != "arm64" {
		return p, errors.New("explicit different published revision and ready deployment required")
	}
	if _, e := os.Lstat(filepath.Join(d.Directory, OperationLock)); !os.IsNotExist(e) {
		return p, errors.New("host operation is active or interrupted")
	}
	if _, e := d.ValidateReceipt(ctx, r); e != nil {
		return p, e
	}
	fact, e := d.upgradeFact(ctx, r)
	if e != nil {
		return p, e
	}
	source, components, services, e := d.targetImages(ctx, r, target, arch, evidence, images)
	if e != nil {
		return p, e
	}
	now := time.Now().Unix()
	p = UpgradePlan{Version: 1, NodeID: fact.NodeID, Project: r.Project, Role: r.Role, Database: r.Database, From: r.Revision, Target: target, SourceSHA: source, Architecture: arch, Generation: migrations.Generation, ReceiptSHA: upgradeHash(r), Images: components, ServiceImages: services, CreatedAt: now, ExpiresAt: now + 3600, RecoveryScope: recovery.UpgradeStateScope}
	p.FromGeneration = fact.Database.SchemaGeneration
	p.SHA256 = p.digest()
	return p, nil
}

func (d *Deployment) saveUpgrade(s UpgradeState) error {
	return replaceJSON(filepath.Join(d.Directory, UpgradeJournal), s)
}
func (d *Deployment) upgradeState() (UpgradeState, error) {
	var s UpgradeState
	raw, e := readRegular(filepath.Join(d.Directory, UpgradeJournal), 2<<20)
	if e != nil {
		return s, e
	}
	if _, e = protocol.ParseStrictJSON(raw, 2<<20); e != nil {
		return s, e
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&s) != nil || s.Version != 1 || s.Plan.SHA256 != s.Plan.digest() {
		return s, errors.New("invalid upgrade journal; preserve recovery materials")
	}
	return s, nil
}

// ApplyUpgrade leaves the native offline gate CLOSED. Opening requires a
// separate confirmed command which verifies the running target before traffic.
func (d *Deployment) ApplyUpgrade(ctx context.Context, r Receipt, p UpgradePlan, approval, node, output string, external bool, evidence Evidence, images Images) (operationResult UpgradeState, operationErr error) {
	var state UpgradeState
	if p.RecoveryScope != recovery.UpgradeStateScope {
		return state, errors.New("regenerate the upgrade plan with mandatory state-only recovery scope")
	}
	if !p.valid(time.Now()) || approval != p.SHA256 || node != p.NodeID || p.ReceiptSHA != upgradeHash(r) || p.From != r.Revision || p.Project != r.Project || p.Role != r.Role || p.Database != r.Database || r.State != "ready" || output == "" {
		return state, errors.New("current plan digest, exact source NodeID and new backup path required")
	}
	if _, e := os.Lstat(output); !os.IsNotExist(e) {
		return state, errors.New("backup output already exists or cannot be inspected")
	}
	if r.Database == "mysql" && !external {
		return state, errors.New("MySQL upgrade requires explicit confirmation that external writers are stopped")
	}
	done, e := d.AcquireOperation()
	if e != nil {
		return state, e
	}
	defer func() { operationErr = errors.Join(operationErr, done()) }()
	if _, e = os.Lstat(filepath.Join(d.Directory, UpgradeJournal)); e == nil {
		prior, err := d.upgradeState()
		if err != nil || prior.Phase != "opened" {
			return state, errors.New("prior upgrade is unfinished; preserve its journal and recovery archive")
		}
		// Keep every previous receipt and recovery reference; never erase history.
		if e = exclusiveJSONOrSame(filepath.Join(d.Directory, ".fc-upgrade-"+prior.Plan.SHA256+".json"), prior); e != nil {
			return state, e
		}
	} else if !os.IsNotExist(e) {
		return state, e
	}
	cfg, e := d.ValidateReceipt(ctx, r)
	if e != nil {
		return state, e
	}
	if _, e = upgradeDataRoot(cfg); e != nil {
		return state, e
	}
	if e = d.localUpgradeEngine(ctx, p.Architecture); e != nil {
		return state, e
	}
	fact, e := d.upgradeFact(ctx, r)
	if e != nil || fact.NodeID != p.NodeID || fact.Database.SchemaGeneration != p.FromGeneration {
		return state, errors.New("source changed since upgrade planning")
	}
	source, components, services, e := d.targetImages(ctx, r, p.Target, p.Architecture, evidence, images)
	if e != nil {
		return state, e
	}
	if source != p.SourceSHA || !reflect.DeepEqual(components, p.Images) || !reflect.DeepEqual(services, p.ServiceImages) {
		return state, errors.New("release proof changed since approval; generate a new plan")
	}
	// Pull before stopping the source. Docker verifies content against each
	// approved immutable digest; a failed pull never triggers a local build.
	for _, name := range sortedServices(p.ServiceImages) {
		if p.ServiceImages[name] != r.ServiceImages[name] {
			if _, e = d.Runner.Run(ctx, "docker", "pull", p.ServiceImages[name]); e != nil {
				return state, errors.New("target image pull failed; running source remains unchanged")
			}
		}
	}
	output, e = filepath.Abs(output)
	if e != nil {
		return state, e
	}
	if e = d.requireUpgradeBackupCapacity(ctx, r, output); e != nil {
		return state, e
	}
	state = UpgradeState{Version: 1, Phase: "backup_pending", Plan: p, Previous: r, BackupFile: output}
	if e = d.saveUpgrade(state); e != nil {
		return state, e
	}
	fail := func(message string) (UpgradeState, error) {
		state.Phase = "failed_fenced"
		if !d.fenceUpgradeFailure(ctx, cfg) {
			state.Phase = "failed_fence_unverified"
		}
		state.Failure = message
		_ = d.saveUpgrade(state)
		return state, errors.New(message + "; preserve the journal, backup and source image locks; no database rollback was attempted")
	}
	backup, e := d.backupLocked(ctx, r, output, true, external)
	if e != nil {
		return fail("consistent backup did not complete")
	}
	if !backup.Verified || backup.Manifest.Scope != recovery.UpgradeStateScope || backup.Manifest.NodeID != p.NodeID || backup.Manifest.Revision != p.From || backup.Manifest.SchemaGeneration != p.FromGeneration {
		return fail("backup identity or integrity verification failed")
	}
	verified, e := recovery.Check(ctx, output, backup.SHA256)
	if e != nil || !verified.Verified {
		return fail("saved backup could not be independently verified")
	}
	state.BackupSHA = backup.SHA256
	state.BackupCleanupWarning = backup.CleanupWarning
	state.BackupScratch = backup.RetainedScratch
	state.BackupCompleteCluster = backup.Manifest.CompleteCluster
	state.Phase = "backed_up_fenced"
	if e = d.saveUpgrade(state); e != nil {
		return fail("backup journal persistence failed")
	}
	return d.prepareUpgradeLocked(ctx, cfg, state)
}

func sortedServices(images map[string]string) []string {
	names := make([]string, 0, len(images))
	for name := range images {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
