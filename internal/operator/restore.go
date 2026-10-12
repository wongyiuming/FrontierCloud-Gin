package operator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

const RecoveredCompose = "docker-compose.recovered.json"
const RestoreJournal = ".fc-restore.json"

type InputRunner interface {
	RunFrom(context.Context, io.Reader, string, ...string) error
}
type RestoreState struct {
	Version          int             `json:"version"`
	NodeID           string          `json:"node_id"`
	ArchiveSHA       string          `json:"archive_sha256"`
	SourceProject    string          `json:"source_project"`
	Project          string          `json:"target_project"`
	Phase            string          `json:"phase"`
	OwnManual        bool            `json:"owns_manual_maintenance"`
	DatabaseImported bool            `json:"database_imported"`
	Report           recovery.Report `json:"recovery"`
}

var composeProject = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// RestoreCheck remains read-only, including the target and Docker engine. It
// validates bytes, required local state and physical capacity before extraction.
func RestoreCheck(ctx context.Context, input, target, expected string) (recovery.Report, error) {
	r, e := recovery.Check(ctx, input, expected)
	if e != nil {
		return r, e
	}
	if target == "" || len(r.Manifest.Missing) > 0 {
		return r, errors.New("restore target or matching related-node recovery state is missing")
	}
	if _, e = os.Lstat(target); !os.IsNotExist(e) {
		return r, errors.New("restore target must not exist")
	}
	parent, e := filepath.Abs(filepath.Dir(target))
	if e != nil {
		return r, e
	}
	info, e := os.Lstat(parent)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return r, errors.New("restore requires an existing real parent directory")
	}
	free, e := diskFree(parent)
	if e != nil {
		return r, e
	}
	required := uint64(r.Manifest.Bytes) + (1 << 30)
	if r.Manifest.Database == "mysql" {
		required += uint64(r.Manifest.Bytes) * 2
	}
	if free < required {
		return r, errors.New("restore filesystem lacks space for material, staging and database import")
	}
	return r, nil
}

// PrepareRestore maps only verified state classes into a new Compose project.
// It creates no container/volume and preserves the offline gate. No initializer
// will substitute a new identity or key for restored material.
func PrepareRestore(ctx context.Context, target, project string, report recovery.Report, runner Runner) (*Deployment, Receipt, error) {
	var empty Receipt
	if !report.Verified || !composeProject.MatchString(project) {
		return nil, empty, errors.New("verified recovery report and explicit valid target project required")
	}
	root, e := filepath.Abs(target)
	if e != nil {
		return nil, empty, e
	}
	directory := filepath.Join(root, "deployment")
	source, old, e := Open(directory)
	if e != nil {
		return nil, empty, e
	}
	source.Runner = runner
	if old.Revision != report.Manifest.Revision || old.Database != report.Manifest.Database || old.Role == "storage" && report.Manifest.Role != "Follower" {
		return nil, empty, errors.New("archived deployment and source identity are incompatible")
	}
	if _, e = os.Lstat(filepath.Join(root, "data", ".frontiercloud-native-maintenance")); e != nil {
		return nil, empty, errors.New("restored offline boundary is missing")
	}
	raw, e := source.Compose(ctx, true, "config", "--format", "json")
	if e != nil {
		return nil, empty, e
	}
	var full map[string]any
	if json.Unmarshal(raw, &full) != nil {
		return nil, empty, errors.New("archived Compose cannot be resolved")
	}
	services, ok := full["services"].(map[string]any)
	if !ok {
		return nil, empty, errors.New("archived services missing")
	}
	full["name"] = project
	classFor := map[string]string{"runtime_secrets": "runtime_secrets", "storage_secrets": "runtime_secrets", "certificate_state": "certificate_state", "certificate_published": "certificate_published", "redis_data": "redis_data"}
	for name, value := range services {
		s, ok := value.(map[string]any)
		if !ok || s["build"] != nil {
			return nil, empty, errors.New("recovery must use recorded images, never builds")
		}
		if old.ServiceImages[name] != s["image"] {
			return nil, empty, errors.New("archived service image differs from its receipt")
		}
		delete(s, "env_file")
		if mounts, ok := s["volumes"].([]any); ok {
			for _, value := range mounts {
				m, ok := value.(map[string]any)
				if !ok {
					return nil, empty, errors.New("invalid archived mount")
				}
				kind, _ := m["type"].(string)
				src, _ := m["source"].(string)
				dst, _ := m["target"].(string)
				if kind == "bind" {
					if dst != "/app/data" {
						return nil, empty, errors.New("unclassified archived bind; recovery cannot relocate it silently")
					}
					m["source"] = filepath.Join(root, "data")
					delete(m, "bind")
				} else if kind == "volume" {
					if class, yes := classFor[src]; yes {
						if info, e := os.Lstat(filepath.Join(root, class)); e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
							return nil, empty, errors.New("required recovered state class is absent or unsafe")
						}
						m["type"] = "bind"
						m["source"] = filepath.Join(root, class)
						delete(m, "volume")
					} else if src != "web_tmp" && src != "certificate_runtime" && src != "mysql_data" {
						return nil, empty, errors.New("unclassified recovery volume")
					}
				}
			}
		}
	}
	if volumes, ok := full["volumes"].(map[string]any); ok {
		for name, value := range volumes {
			v, ok := value.(map[string]any)
			if !ok || v["external"] == true {
				return nil, empty, errors.New("external recovery volume is not allowed")
			}
			v["name"] = project + "_" + name
		}
	}
	if networks, ok := full["networks"].(map[string]any); ok {
		for name, value := range networks {
			n, ok := value.(map[string]any)
			if !ok || n["external"] == true {
				return nil, empty, errors.New("external recovery network is not allowed")
			}
			n["name"] = project + "_" + name
		}
	}
	if e = exclusiveJSON(filepath.Join(directory, RecoveredCompose), full); e != nil {
		return nil, empty, e
	}
	locked := map[string]map[string]string{}
	for name, image := range old.ServiceImages {
		locked[name] = map[string]string{"image": image}
	}
	if e = replaceJSON(filepath.Join(directory, ImagesFile), map[string]any{"services": locked}); e != nil {
		return nil, empty, e
	}
	d := &Deployment{Directory: directory, Role: old.Role, Files: []string{RecoveredCompose}, Runner: runner, Project: project}
	cfg, e := d.Config(ctx, false)
	if e != nil {
		return nil, empty, e
	}
	// Check namespace collisions before changing the operational receipt.
	ids, e := d.Compose(ctx, false, "ps", "--all", "--quiet")
	if e != nil {
		return nil, empty, e
	}
	if strings.TrimSpace(string(ids)) != "" {
		return nil, empty, errors.New("target Compose project already has containers")
	}
	vols, e := runner.Run(ctx, "docker", "volume", "ls", "--format", "{{.Name}}")
	if e != nil {
		return nil, empty, e
	}
	existing := map[string]bool{}
	for _, name := range strings.Fields(string(vols)) {
		existing[name] = true
	}
	for _, v := range cfg.Volumes {
		if existing[v.Name] {
			return nil, empty, errors.New("target project has an existing volume; recovery refuses takeover")
		}
	}
	old.Project = project
	old.Files = append([]string(nil), d.Files...)
	old.SelectionHash = selectionHash(cfg)
	old.Recovered = true
	old.State = "restored_fenced"
	if e = replaceJSON(filepath.Join(directory, ReceiptFile), old); e != nil {
		return nil, empty, e
	}
	state := RestoreState{Version: 1, NodeID: report.Manifest.NodeID, ArchiveSHA: report.SHA256, SourceProject: sourceProject(raw), Project: project, Phase: "prepared", Report: report}
	if e = exclusiveJSON(filepath.Join(directory, RestoreJournal), state); e != nil {
		return nil, empty, e
	}
	return d, old, nil
}
func sourceProject(raw []byte) string { var c Config; _ = json.Unmarshal(raw, &c); return c.Name }
func (d *Deployment) restoreState() (RestoreState, error) {
	var s RestoreState
	raw, e := readRegular(filepath.Join(d.Directory, RestoreJournal), 32<<20)
	if e != nil {
		return s, e
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&s) != nil || s.Version != 1 || s.NodeID == "" || s.Project == "" {
		return s, errors.New("invalid persistent restore journal")
	}
	return s, nil
}
func (d *Deployment) saveRestore(s RestoreState) error {
	return replaceJSON(filepath.Join(d.Directory, RestoreJournal), s)
}

// ActivateRestore starts an already verified restored identity behind manual
// maintenance. Opening public traffic is a separate explicit command.
func (d *Deployment) ActivateRestore(ctx context.Context, r Receipt, confirmation string, sourceOffline bool) (RestoreState, error) {
	var state RestoreState
	done, e := d.AcquireOperation()
	if e != nil {
		return state, e
	}
	defer done()
	cfg, e := d.ValidateReceipt(ctx, r)
	if e != nil {
		return state, e
	}
	state, e = d.restoreState()
	if e != nil {
		return state, e
	}
	if !r.Recovered || confirmation != state.NodeID || !sourceOffline {
		return state, errors.New("restored NodeID confirmation and explicit source-offline confirmation required")
	}
	if state.Phase == "verified" || state.Phase == "opened" {
		return state, nil
	}
	// A source on this engine must actually be stopped; an operator attestation
	// cannot override known running containers with the original project name.
	ids, e := d.Runner.Run(ctx, "docker", "ps", "--filter", "label=com.docker.compose.project="+state.SourceProject, "--filter", "label=com.docker.compose.service=web", "--format", "{{.ID}}")
	if e != nil || strings.TrimSpace(string(ids)) != "" {
		return state, errors.New("source business process is still running or its state cannot be verified")
	}
	data := filepath.Join(filepath.Dir(d.Directory), "data")
	manual := filepath.Join(data, sitecontrol.Manual)
	if _, e = os.Lstat(manual); os.IsNotExist(e) {
		f, e := os.OpenFile(manual, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return state, e
		}
		ownerRoot, e := os.OpenRoot(data)
		if e != nil {
			f.Close()
			return state, e
		}
		e = fsutil.InheritOwner(f, ownerRoot)
		ownerRoot.Close()
		if e != nil {
			f.Close()
			return state, e
		}
		_, e = f.WriteString("manual\n")
		if e == nil {
			e = f.Sync()
		}
		e = errors.Join(e, f.Close())
		if e != nil {
			return state, e
		}
		state.OwnManual = true
	} else if e != nil {
		return state, e
	}
	state.Phase = "activating"
	if e = d.saveRestore(state); e != nil {
		return state, e
	}
	fail := func(cause error) (RestoreState, error) {
		state.Phase = "failed_fenced"
		_ = d.saveRestore(state)
		_, _ = d.Compose(context.WithoutCancel(ctx), true, "stop", "web")
		fenceCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		_, _ = d.Compose(fenceCtx, true, "run", "--rm", "--no-deps", "-T", "web", "maintenance", "enter")
		return state, cause
	}
	// Start only restored state consumers. Fresh data/key initializers never run.
	dependencies := []string{"certificate-init", "redis"}
	if r.Database == "mysql" {
		dependencies = append(dependencies, "mysql")
	}
	var selected []string
	for _, name := range dependencies {
		if _, ok := cfg.Services[name]; ok {
			selected = append(selected, name)
		}
	}
	if len(selected) > 0 {
		if _, e = d.Compose(ctx, true, append([]string{"up", "-d", "--no-build", "--pull", "never", "--no-deps"}, selected...)...); e != nil {
			return fail(errors.New("recovery infrastructure startup failed; material remains fenced"))
		}
	}
	if r.Database == "mysql" && !state.DatabaseImported {
		stream, ok := d.Runner.(InputRunner)
		if !ok {
			return fail(errors.New("bounded MySQL restoration input unavailable"))
		}
		for {
			if _, e = d.Compose(ctx, true, "exec", "-T", "mysql", "sh", "-c", `MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) mysqladmin ping -h 127.0.0.1 -u root --silent`); e == nil {
				break
			}
			select {
			case <-ctx.Done():
				return fail(ctx.Err())
			case <-time.After(time.Second):
			}
		}
		dump, e := os.Open(filepath.Join(filepath.Dir(d.Directory), "mysql_dump", "database.sql"))
		if e != nil {
			return fail(e)
		}
		e = stream.RunFrom(ctx, dump, "docker", append(d.composeArgs(true), "exec", "-T", "mysql", "sh", "-c", `MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) exec mysql -u root`)...)
		dump.Close()
		if e != nil {
			return fail(errors.New("MySQL import failed; target remains private and fenced; do not start business writers"))
		}
		state.DatabaseImported = true
		if e = d.saveRestore(state); e != nil {
			return fail(e)
		}
	}
	fact, e := d.runtimeFact(ctx)
	if e != nil || fact.NodeID != state.NodeID || fact.Database.SchemaGeneration != state.Report.Manifest.SchemaGeneration || !fact.NativeMaintenance || !fact.Database.LogicalIdle {
		return fail(errors.New("restored database/identity/transaction verification failed"))
	}
	if _, e = d.Compose(ctx, true, "run", "--rm", "--no-deps", "-T", "web", "maintenance", "resume"); e != nil {
		return fail(errors.New("verified native recovery could not resume; public maintenance remains closed"))
	}
	var resident []string
	for name := range cfg.Services {
		if !strings.HasSuffix(name, "-init") {
			resident = append(resident, name)
		}
	}
	sort.Strings(resident)
	if _, e = d.Compose(ctx, true, append([]string{"up", "-d", "--no-build", "--pull", "never", "--no-deps", "--wait", "--wait-timeout", "120"}, resident...)...); e != nil {
		return fail(errors.New("restored services failed readiness; public maintenance remains closed"))
	}
	if _, e = d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "recovery-verify"); e != nil {
		return fail(errors.New("restored business resource verification failed; public maintenance remains closed"))
	}
	state.Phase = "verified"
	state.Report.RestoreReady = true
	state.Report.BusinessVerified = true
	if e = d.saveRestore(state); e != nil {
		return fail(e)
	}
	return state, nil
}

func (d *Deployment) OpenRestore(ctx context.Context, r Receipt, confirmation string) (RestoreState, error) {
	var state RestoreState
	done, e := d.AcquireOperation()
	if e != nil {
		return state, e
	}
	defer done()
	if _, e = d.ValidateReceipt(ctx, r); e != nil {
		return state, e
	}
	state, e = d.restoreState()
	if e != nil {
		return state, e
	}
	if !r.Recovered || state.NodeID != confirmation || state.Phase != "verified" || !state.OwnManual {
		return state, errors.New("opening requires a verified restored identity and maintenance owned by this restore; prior administrator maintenance is preserved")
	}
	if _, e = d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "recovery-verify"); e != nil {
		return state, e
	}
	data, e := os.OpenRoot(filepath.Join(filepath.Dir(d.Directory), "data"))
	if e != nil {
		return state, e
	}
	defer data.Close()
	content, e := data.ReadFile(sitecontrol.Manual)
	if e != nil || string(content) != "manual\n" {
		return state, errors.New("maintenance state changed; refused to reopen")
	}
	refence := func() {
		f, err := data.OpenFile(sitecontrol.Manual, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			_ = fsutil.InheritOwner(f, data)
			_, _ = f.WriteString("manual\n")
			_ = f.Sync()
			_ = f.Close()
		}
		_ = fsutil.SyncDirectory(data, ".")
	}
	if e = data.Remove(sitecontrol.Manual); e != nil {
		return state, e
	}
	if e = fsutil.SyncDirectory(data, "."); e != nil {
		refence()
		return state, e
	}
	state.OwnManual = false
	state.Phase = "opened"
	e = d.saveRestore(state)
	if e != nil {
		refence()
		state.OwnManual = true
		state.Phase = "verified"
	}
	return state, e
}
