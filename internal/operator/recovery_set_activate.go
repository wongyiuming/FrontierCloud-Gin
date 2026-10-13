package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

const RestoreSetJournal = ".fc-restore-set.json"
const RecoverySetMarker = ".fc-recovery-set.json"

type RestoreSetState struct {
	Version       int                `json:"version"`
	Phase         string             `json:"phase"`
	Source        string             `json:"source_set_directory"`
	Target        string             `json:"target_material_directory"`
	ProjectPrefix string             `json:"project_prefix"`
	Report        recovery.SetReport `json:"recovery_set"`
	Projects      map[string]string  `json:"projects"`
	Members       map[string]string  `json:"members"`
	Failure       string             `json:"failure,omitempty"`
}
type RecoveryRunnerFactory func(string) Runner

func saveRestoreSet(s RestoreSetState) error {
	return replaceJSON(filepath.Join(s.Target, RestoreSetJournal), s)
}
func readRestoreSet(target string) (RestoreSetState, error) {
	var s RestoreSetState
	raw, e := readRegular(filepath.Join(target, RestoreSetJournal), 2<<20)
	if e != nil {
		return s, e
	}
	if _, e = protocol.ParseStrictJSON(raw, 2<<20); e != nil {
		return s, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || s.Version != 1 || s.Target != target || !s.Report.Verified || recovery.ValidateSetGraph(s.Report.Manifest) != nil {
		return s, errors.New("invalid persistent cluster restoration journal")
	}
	return s, nil
}

func checkRestoreSetSource(ctx context.Context, state RestoreSetState) error {
	checked, e := recovery.CheckSet(ctx, state.Source, state.Report.SHA256)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(checked.Manifest, state.Report.Manifest) {
		return errors.New("restore journal differs from its approved archive set")
	}
	return nil
}

func setMaterialMarker(target string, report recovery.SetReport) error {
	for _, member := range report.Manifest.Members {
		raw, e := readRegular(filepath.Join(target, member.NodeID, "deployment", RecoverySetMarker), 2<<20)
		if e != nil {
			return e
		}
		var recorded recovery.SetReport
		if _, e = protocol.ParseStrictJSON(raw, 2<<20); e != nil {
			return e
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&recorded) != nil || recorded.SHA256 != report.SHA256 || recorded.Manifest.ID != report.Manifest.ID || recorded.Manifest.MasterID != report.Manifest.MasterID {
			return errors.New("restored member does not belong to this verified recovery set")
		}
	}
	return nil
}

// PrepareRestoreSet verifies every extracted byte before rewriting deployment
// metadata. All target native leases remain held during preparation, and no
// container starts. Each member receives a distinct new Compose project.
func PrepareRestoreSet(ctx context.Context, source, target, expected, master, prefix string, runners RecoveryRunnerFactory) (operationResult RestoreSetState, operationErr error) {
	var state RestoreSetState
	source, e := filepath.Abs(source)
	if e != nil {
		return state, e
	}
	target, e = filepath.Abs(target)
	if e != nil {
		return state, e
	}
	if runners == nil || !composeProject.MatchString(prefix) || len(prefix) > 29 {
		return state, errors.New("valid bounded project prefix and local runner required")
	}
	result, e := recovery.CheckSet(ctx, source, expected)
	if e != nil {
		return state, e
	}
	if expected == "" || result.Manifest.MasterID != master {
		return state, errors.New("exact set digest and original Master NodeID required")
	}
	if e = setMaterialMarker(target, result); e != nil {
		return state, e
	}
	done, e := (&Deployment{Directory: target}).AcquireOperation()
	if e != nil {
		return state, e
	}
	defer func() { operationErr = errors.Join(operationErr, done()) }()
	resuming := false
	if _, e = os.Lstat(filepath.Join(target, RestoreSetJournal)); !os.IsNotExist(e) {
		state, e = readRestoreSet(target)
		if e != nil || state.Phase != "preparing_fenced" || state.Source != source || state.ProjectPrefix != prefix || state.Report.SHA256 != expected || !reflect.DeepEqual(state.Report.Manifest, result.Manifest) {
			return state, errors.New("restoration set has a different or non-resumable intent; preserve its journal")
		}
		resuming = true
		if len(state.Projects) != len(result.Manifest.Members) || len(state.Members) != len(result.Manifest.Members) {
			return state, errors.New("interrupted set member selection changed")
		}
	} else {
		state = RestoreSetState{Version: 1, Phase: "preparing_fenced", Source: source, Target: target, ProjectPrefix: prefix, Report: result, Projects: map[string]string{}, Members: map[string]string{}}
	}
	var gates []*maintenance.Gate
	defer func() {
		for _, gate := range gates {
			gate.Close()
		}
	}()
	for _, member := range result.Manifest.Members {
		root := filepath.Join(target, member.NodeID)
		r, e := recovery.Check(ctx, filepath.Join(source, member.Archive), member.SHA256)
		if e != nil {
			return state, e
		}
		checkMaterial := recovery.CheckMaterial
		if resuming {
			checkMaterial = recovery.CheckPreparingMaterial
		}
		if e = checkMaterial(ctx, root, r); e != nil {
			return state, errors.New("extracted member changed before preparation")
		}
		d := &Deployment{Directory: filepath.Join(root, "deployment"), Runner: runners(filepath.Join(root, "deployment"))}
		arch, e := d.Runner.Run(ctx, "docker", "info", "--format", "{{.Architecture}}")
		if e != nil {
			return state, e
		}
		if e = d.localUpgradeEngine(ctx, Architecture(strings.TrimSpace(string(arch)))); e != nil {
			return state, e
		}
		gate, e := maintenance.Open(filepath.Join(root, "data"))
		if e != nil {
			return state, e
		}
		gates = append(gates, gate)
		project := prefix + "-" + member.NodeID
		if resuming && (state.Projects[member.NodeID] != project || (state.Members[member.NodeID] != "material_verified" && state.Members[member.NodeID] != "prepared_fenced")) {
			return state, errors.New("interrupted member project/checkpoint changed")
		}
		state.Projects[member.NodeID] = project
		if !resuming {
			state.Members[member.NodeID] = "material_verified"
		}
	}
	if !resuming {
		e = exclusiveJSON(filepath.Join(target, RestoreSetJournal), state)
	}
	if e != nil {
		return state, e
	}
	var prepare func(int) error
	prepare = func(index int) error {
		if index < len(gates) {
			return gates[index].Inspect(ctx, func(context.Context) error { return prepare(index + 1) })
		}
		for _, member := range result.Manifest.Members {
			root := filepath.Join(target, member.NodeID)
			r, e := recovery.Check(ctx, filepath.Join(source, member.Archive), member.SHA256)
			if e != nil {
				return e
			}
			// Recheck under the common target fence. Do not substitute newly
			// generated identities or secrets for incomplete restored material.
			checkMaterial := recovery.CheckMaterial
			if resuming {
				checkMaterial = recovery.CheckPreparingMaterial
			}
			if e = checkMaterial(ctx, root, r); e != nil {
				return e
			}
			journal, journalErr := (&Deployment{Directory: filepath.Join(root, "deployment")}).restoreState()
			if resuming && journalErr == nil && journal.Phase == "prepared" {
				d, _, err := openRestoredMember(ctx, state, member, runners)
				if err != nil || journal.NodeID != member.NodeID || journal.ArchiveSHA != member.SHA256 || journal.Project != state.Projects[member.NodeID] {
					return errors.New("prepared member changed during interrupted set preparation")
				}
				ids, err := d.Compose(ctx, true, "ps", "--all", "--quiet")
				if err != nil || strings.TrimSpace(string(ids)) != "" {
					return errors.New("prepared member unexpectedly has containers")
				}
			} else if _, _, e = PrepareRestore(ctx, root, state.Projects[member.NodeID], r, runners(filepath.Join(root, "deployment"))); e != nil {
				return e
			}
			state.Members[member.NodeID] = "prepared_fenced"
			if e = saveRestoreSet(state); e != nil {
				return e
			}
		}
		return nil
	}
	if e = prepare(0); e != nil {
		state.Phase = "failed_fenced"
		state.Failure = "set preparation failed; original archives and extracted materials retained"
		_ = saveRestoreSet(state)
		return state, e
	}
	state.Phase = "prepared_fenced"
	e = saveRestoreSet(state)
	return state, e
}

func orderedSetMembers(m recovery.SetManifest) []recovery.SetMember {
	members := append([]recovery.SetMember(nil), m.Members...)
	sort.Slice(members, func(i, j int) bool {
		if members[i].NodeID == m.MasterID {
			return false
		}
		if members[j].NodeID == m.MasterID {
			return true
		}
		return members[i].NodeID < members[j].NodeID
	})
	return members
}

func openRestoredMember(ctx context.Context, state RestoreSetState, member recovery.SetMember, runners RecoveryRunnerFactory) (*Deployment, Receipt, error) {
	d, r, e := Open(filepath.Join(state.Target, member.NodeID, "deployment"))
	if e != nil {
		return nil, r, e
	}
	d.Runner = runners(d.Directory)
	if !r.Recovered || r.Project != state.Projects[member.NodeID] || r.Revision != member.Revision || r.Database != member.Database {
		return nil, r, errors.New("prepared member receipt changed")
	}
	if _, e = d.ValidateReceipt(ctx, r); e != nil {
		return nil, r, e
	}
	arch, e := d.Runner.Run(ctx, "docker", "info", "--format", "{{.Architecture}}")
	if e != nil {
		return nil, r, e
	}
	if e = d.localUpgradeEngine(ctx, Architecture(strings.TrimSpace(string(arch)))); e != nil {
		return nil, r, e
	}
	return d, r, nil
}

func refenceRestoreSet(ctx context.Context, state *RestoreSetState, runners RecoveryRunnerFactory, message string) (RestoreSetState, error) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(len(state.Report.Manifest.Members))*45*time.Second)
	defer cancel()
	ctx = cleanup
	state.Phase = "failed_fenced"
	state.Failure = message
	for _, member := range state.Report.Manifest.Members {
		d, r, e := openRestoredMember(ctx, *state, member, runners)
		if e != nil {
			state.Phase = "failed_fence_unverified"
			continue
		}
		cfg, e := d.ValidateReceipt(ctx, r)
		if e != nil || !d.fenceUpgradeFailure(ctx, cfg) {
			state.Phase = "failed_fence_unverified"
		}
	}
	_ = saveRestoreSet(*state)
	return *state, errors.New(message + "; recovery set and individual journals retained, no automatic rollback or public reopening")
}

func checkRestoredSet(ctx context.Context, state RestoreSetState, runners RecoveryRunnerFactory) error {
	observed := state.Report.Manifest
	observed.Members = nil
	for _, member := range state.Report.Manifest.Members {
		d, r, e := openRestoredMember(ctx, state, member, runners)
		if e != nil {
			return e
		}
		fact, e := d.runtimeFact(ctx)
		if e != nil || fact.NodeID != member.NodeID || fact.NativeMaintenance || !fact.Database.LogicalIdle || fact.Database.SchemaGeneration != member.Generation {
			return errors.New("restored member identity/schema/transaction state is not ready")
		}
		if _, e = d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "recovery-verify"); e != nil {
			return errors.New("restored member managed resource reads failed")
		}
		if _, e = d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "healthcheck"); e != nil {
			return errors.New("restored member health failed")
		}
		observed.Members = append(observed.Members, setMemberFact(r, fact))
	}
	if recovery.ValidateSetGraph(observed) != nil {
		return errors.New("restored reciprocal relationship graph does not match a complete cluster")
	}
	return nil
}

// ActivateRestoreSet starts followers before Master, each under public manual
// maintenance. A failure refences every prepared member. Opening is separate.
func ActivateRestoreSet(ctx context.Context, target, expected, master string, allSourcesOffline bool, runners RecoveryRunnerFactory) (operationResult RestoreSetState, operationErr error) {
	var empty RestoreSetState
	target, e := filepath.Abs(target)
	if e != nil {
		return empty, e
	}
	if !allSourcesOffline || runners == nil {
		return empty, errors.New("explicit all-source-identities-offline confirmation required")
	}
	done, e := (&Deployment{Directory: target}).AcquireOperation()
	if e != nil {
		return empty, e
	}
	defer func() { operationErr = errors.Join(operationErr, done()) }()
	state, e := readRestoreSet(target)
	if e != nil {
		return state, e
	}
	if (state.Phase != "prepared_fenced" && state.Phase != "activating_fenced") || state.Report.SHA256 != expected || state.Report.Manifest.MasterID != master {
		return state, errors.New("exact prepared set digest and Master NodeID required")
	}
	if e = checkRestoreSetSource(ctx, state); e != nil {
		return state, e
	}
	if e = setMaterialMarker(target, state.Report); e != nil {
		return state, e
	}
	state.Phase = "activating_fenced"
	if e = saveRestoreSet(state); e != nil {
		return state, e
	}
	for _, member := range orderedSetMembers(state.Report.Manifest) {
		d, r, e := openRestoredMember(ctx, state, member, runners)
		if e != nil {
			return refenceRestoreSet(ctx, &state, runners, "member deployment binding failed")
		}
		if _, e = d.activateRestore(ctx, r, member.NodeID, true, true); e != nil {
			return refenceRestoreSet(ctx, &state, runners, "member activation failed")
		}
		state.Members[member.NodeID] = "verified_fenced"
		if e = saveRestoreSet(state); e != nil {
			return refenceRestoreSet(ctx, &state, runners, "member verification receipt could not be persisted")
		}
	}
	if e = checkRestoredSet(ctx, state, runners); e != nil {
		return refenceRestoreSet(ctx, &state, runners, "whole-set identity/relationship/business verification failed")
	}
	state.Phase = "verified_fenced"
	state.Report.BusinessVerified = true
	if e = saveRestoreSet(state); e != nil {
		return refenceRestoreSet(ctx, &state, runners, "set verification receipt could not be persisted")
	}
	return state, nil
}

// OpenRestoreSet rechecks the whole set then opens Master LAST. It never treats
// one successfully restored member as permission to open a partial cluster.
func OpenRestoreSet(ctx context.Context, target, expected, master string, runners RecoveryRunnerFactory) (operationResult RestoreSetState, operationErr error) {
	var empty RestoreSetState
	target, e := filepath.Abs(target)
	if e != nil {
		return empty, e
	}
	if runners == nil {
		return empty, errors.New("local restore runners required")
	}
	done, e := (&Deployment{Directory: target}).AcquireOperation()
	if e != nil {
		return empty, e
	}
	defer func() { operationErr = errors.Join(operationErr, done()) }()
	state, e := readRestoreSet(target)
	if e != nil {
		return state, e
	}
	if !state.Report.BusinessVerified || state.Report.SHA256 != expected || state.Report.Manifest.MasterID != master {
		return state, errors.New("verified whole-set digest and original Master NodeID required")
	}
	if state.Phase == "opened" || state.Phase == "opened_cleanup_pending" {
		return finishRestoreSetMarkers(state)
	}
	if state.Phase != "verified_fenced" && state.Phase != "opening" {
		return state, errors.New("set is not verified for public opening")
	}
	resuming := state.Phase == "opening"
	if e = setMaterialMarker(target, state.Report); e != nil {
		if resuming {
			return refenceRestoreSet(ctx, &state, runners, "interrupted set opening marker could not be restored")
		}
		return state, e
	}
	if e = checkRestoreSetSource(ctx, state); e != nil {
		if resuming {
			return refenceRestoreSet(ctx, &state, runners, "source changed during interrupted set opening")
		}
		return state, e
	}
	if e = checkRestoredSet(ctx, state, runners); e != nil {
		if resuming {
			return refenceRestoreSet(ctx, &state, runners, "member changed during interrupted set opening")
		}
		return state, e
	}
	state.Phase = "opening"
	if e = saveRestoreSet(state); e != nil {
		return state, e
	}
	for _, member := range orderedSetMembers(state.Report.Manifest) {
		d, r, e := openRestoredMember(ctx, state, member, runners)
		if e != nil {
			return refenceRestoreSet(ctx, &state, runners, "member changed before public opening")
		}
		if _, e = d.openRestore(ctx, r, member.NodeID, true); e != nil {
			return refenceRestoreSet(ctx, &state, runners, "member public opening failed")
		}
		state.Members[member.NodeID] = "opened"
		if e = saveRestoreSet(state); e != nil {
			return refenceRestoreSet(ctx, &state, runners, "member opening receipt could not be persisted")
		}
	}
	state.Phase = "opened_cleanup_pending"
	if e = saveRestoreSet(state); e != nil {
		return refenceRestoreSet(ctx, &state, runners, "set opening receipt could not be persisted")
	}
	return finishRestoreSetMarkers(state)
}

// An interrupted marker cleanup is retried without reopening nodes or changing
// data. Its durable phase reports that public opening has already completed.
func finishRestoreSetMarkers(state RestoreSetState) (RestoreSetState, error) {
	for _, member := range state.Report.Manifest.Members {
		root, e := os.OpenRoot(filepath.Join(state.Target, member.NodeID, "deployment"))
		if e != nil {
			return state, e
		}
		e = root.Remove(RecoverySetMarker)
		if os.IsNotExist(e) {
			e = nil
		}
		if e == nil {
			e = fsutil.SyncDirectory(root, ".")
		}
		root.Close()
		if e != nil {
			return state, e
		}
	}
	state.Phase = "opened"
	return state, saveRestoreSet(state)
}
