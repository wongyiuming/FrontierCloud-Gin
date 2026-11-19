//go:build linux

package operator

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

const treeCaptureLabel = "frontiercloud.tree-backup"

// captureTreeRuntimeStateLocked is only the Master state-archive primitive.
// The caller owns the host operation lock and must prove retained Owner state
// through authorize. The child owns the native/SQLite/tree leases. Neither
// authorize nor the caller may take a competing native lease during capture.
func (d *Deployment) captureTreeRuntimeStateLocked(ctx context.Context, receipt Receipt, output string, authorize func(context.Context, RuntimeFact) error) (report recovery.Report, err error) {
	stream, ok := d.Runner.(treeDuplexRunner)
	if !ok || ctx == nil || authorize == nil || receipt.Role != "master" || receipt.Database != "sqlite" || receipt.State != "ready" {
		return report, errors.New("tree capture requires duplex transport and retained Owner authorization")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if err = d.stoppedWriters(ctx); err != nil {
		return report, err
	}
	plan, err := d.treeBackupRuntimePreflightScope(ctx, receipt, output, recovery.UpgradeStateScope)
	if err != nil {
		return report, err
	}
	if restored, e := d.restoreState(); e == nil {
		if restored.Phase != "opened" || restored.StageCleanupWarning != "" {
			return report, errors.New("unfinished restoration blocks tree capture")
		}
		if restored.ManualStaged {
			if _, e = os.Lstat(filepath.Join(plan.dataRoot, restoreManualStage)); !os.IsNotExist(e) {
				return report, errors.New("finish recorded restore-stage cleanup before tree capture")
			}
		}
	} else if !os.IsNotExist(e) {
		return report, e
	}
	cfg, err := d.ValidateReceipt(ctx, receipt)
	if err != nil {
		return report, err
	}
	fact, err := d.runtimeFact(ctx)
	if err != nil {
		return report, err
	}
	relations, err := treeCaptureOfflineFact(plan, fact)
	if err != nil {
		return report, err
	}
	dbPath := cfg.Services["web"].Environment["SQLITE_PATH"]
	dataPath := cfg.Services["web"].Environment["DATA_ROOT"]
	if !strings.HasPrefix(dbPath, dataPath+"/") {
		return report, errors.New("tree capture SQLite path is outside DATA_ROOT")
	}
	database := strings.TrimPrefix(dbPath, dataPath+"/")
	selection, err := upgradeDataSelection(cfg, receipt)
	if err != nil {
		return report, err
	}
	selection = append(selection, sealedtree.MasterStatePaths()...)
	manifest := recovery.Manifest{NodeID: fact.NodeID, Role: fact.Role, Revision: receipt.Revision, Database: receipt.Database,
		SchemaGeneration: fact.Database.SchemaGeneration, Scope: plan.scope, Consistency: "native-offline-and-deployment-writers-stopped",
		Relations: relations, KeyReferences: []string{"runtime_secrets/tree-master.key", "runtime_secrets/node-vault.key", adminKeyArchivePath}}
	for _, relation := range relations {
		manifest.Missing = append(manifest.Missing, "matching recovery state for related node "+relation.NodeID+" is not included")
	}
	paths := []string{plan.dataRoot, plan.secretsRoot, plan.tmpRoot, filepath.Dir(plan.output)}
	directories := make(map[string]os.FileInfo, len(paths))
	for _, name := range paths {
		info, e := os.Lstat(name)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return report, errors.New("tree capture root unavailable")
		}
		directories[name] = info
	}
	filePins := map[string]os.FileInfo{}
	for _, name := range manifest.KeyReferences {
		file := filepath.Join(plan.secretsRoot, path.Base(name))
		info, e := os.Lstat(file)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() == 0 {
			return report, errors.New("tree capture key unavailable")
		}
		filePins[file] = info
	}
	for class, root := range map[string]string{"data/media-keys": filepath.Join(plan.dataRoot, "media-keys"), "runtime_secrets": plan.secretsRoot} {
		file := filepath.Join(root, "media-premaster.key")
		info, e := os.Lstat(file)
		if os.IsNotExist(e) {
			filePins[file] = nil
			continue
		}
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 32 {
			return report, errors.New("tree capture media key is unsafe")
		}
		filePins[file] = info
		manifest.KeyReferences = append(manifest.KeyReferences, class+"/media-premaster.key")
	}
	sort.Strings(manifest.KeyReferences)

	var nonceBytes [32]byte
	if _, err = rand.Read(nonceBytes[:]); err != nil {
		return report, err
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	parentPath := filepath.Dir(plan.output)
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return report, err
	}
	defer parent.Close()
	parentInfo, err := parent.Stat(".")
	if err != nil || !sameTreeRuntimeDirectory(directories[parentPath], parentInfo) {
		return report, errors.New("tree capture output parent changed")
	}
	workspaceName := ".fc-tree-host-" + nonce
	if err = parent.Mkdir(workspaceName, 0700); err != nil {
		return report, err
	}
	workspaceInfo, err := parent.Lstat(workspaceName)
	if err != nil || !workspaceInfo.IsDir() || workspaceInfo.Mode().Perm() != 0700 {
		return report, errors.New("private tree capture staging unavailable")
	}
	var scratchRoot *os.Root
	var childScratch os.FileInfo
	var reply runtimefacts.TreeBackupCaptureReply
	defer func() {
		cleanup := removeTreeCaptureDirectory(parent, workspaceName, workspaceInfo)
		retained := filepath.Join(parentPath, workspaceName)
		if scratchRoot != nil {
			if childErr := removeTreeCaptureDirectory(scratchRoot, reply.Scratch, childScratch); childErr != nil {
				cleanup = errors.Join(cleanup, childErr)
				retained = filepath.Join(plan.tmpRoot, reply.Scratch)
			}
			_ = scratchRoot.Close()
		}
		if cleanup != nil && report.Verified {
			report.CleanupWarning = "verified tree archive retained; private capture staging cleanup requires operator attention"
			report.RetainedScratch = retained
		} else if cleanup != nil {
			err = errors.Join(err, cleanup)
		}
	}()
	workspace, err := parent.OpenRoot(workspaceName)
	if err != nil {
		return report, err
	}
	defer workspace.Close()
	if opened, e := workspace.Stat("."); e != nil || !sameTreeRuntimeDirectory(workspaceInfo, opened) {
		return report, errors.New("private tree capture staging changed")
	}
	sources, err := d.treeCaptureStateSources(ctx, receipt, cfg, plan, workspace, filePins)
	if err != nil {
		return report, err
	}
	request := runtimefacts.TreeBackupCaptureRequest{Nonce: nonce, DatabaseRelative: database, Selection: selection,
		Manifest: manifest, StageLimit: plan.stagingLimit}
	for _, source := range sources {
		info, e := os.Lstat(source.Directory)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return report, errors.New("tree capture state source unavailable")
		}
		directories[source.Directory] = info
		request.Classes = append(request.Classes, source.Class)
	}
	recheck := func() error {
		current, e := d.ValidateReceipt(ctx, receipt)
		if e != nil {
			return e
		}
		if e = d.stoppedWriters(ctx); e != nil {
			return e
		}
		if e = d.validateBackupAdmission(ctx, current, receipt, fact); e != nil {
			return e
		}
		for name, pinned := range directories {
			info, e := os.Lstat(name)
			if e != nil || !sameTreeRuntimeDirectory(pinned, info) {
				return errors.New("tree capture root changed")
			}
		}
		for name, pinned := range filePins {
			info, e := os.Lstat(name)
			if pinned == nil && os.IsNotExist(e) {
				continue
			}
			if e != nil || !sameTreeRuntimeFile(pinned, info) {
				return errors.New("tree capture state source changed")
			}
		}
		if e = authorize(ctx, fact); e != nil {
			return errors.New("retained Owner authorization is unavailable or changed")
		}
		return nil
	}
	if err = recheck(); err != nil {
		return report, err
	}
	name := "fc-tree-backup-" + nonce
	args := treeCaptureCreateArgs(plan, name, nonce)
	childRemoved := false
	defer func() {
		if childRemoved {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		err = errors.Join(err, d.removeTreeCaptureContainer(cleanupCtx, plan, name, nonce))
	}()
	rawID, err := d.Runner.Run(ctx, "docker", args...)
	if err != nil {
		return report, err
	}
	id := strings.TrimSpace(string(rawID))
	child, err := d.treeCaptureContainer(ctx, plan, name, nonce)
	if err != nil || child.ID != id || child.Status != "created" {
		return report, errors.New("tree capture child identity unavailable")
	}
	if err = stream.RunDuplex(ctx, "docker", []string{"container", "start", "--attach", "--interactive", id}, func(input io.WriteCloser, output *bufio.Reader) error {
		reply, err = treeCaptureExchange(ctx, input, output, plan, request, sources, recheck)
		return err
	}); err != nil {
		return report, err
	}
	child, err = d.treeCaptureContainer(ctx, plan, name, nonce)
	if err != nil || child.ID != id || child.Status != "exited" || child.ExitCode != 0 {
		return report, errors.New("tree capture child completion could not be verified")
	}
	scratchRoot, err = os.OpenRoot(plan.tmpRoot)
	if err != nil {
		return report, err
	}
	rootInfo, err := scratchRoot.Stat(".")
	if err != nil || !sameTreeRuntimeDirectory(directories[plan.tmpRoot], rootInfo) {
		return report, errors.New("tree capture staging root changed")
	}
	childScratch, err = scratchRoot.Lstat(reply.Scratch)
	if err != nil || !childScratch.IsDir() || childScratch.Mode().Perm() != 0700 {
		return report, errors.New("tree capture staging directory changed")
	}
	if _, err = d.Runner.Run(ctx, "docker", "container", "rm", id); err != nil {
		return report, errors.New("completed tree capture child could not be removed")
	}
	childRemoved = true
	verifiedFact, err := d.runtimeFact(ctx)
	if err != nil {
		return report, err
	}
	verifiedRelations, err := treeCaptureOfflineFact(plan, verifiedFact)
	if err != nil || !maps.Equal(fact.Database.Pending, verifiedFact.Database.Pending) || !slices.Equal(relations, verifiedRelations) {
		return report, errors.New("offline tree capture facts changed")
	}
	if err = recheck(); err != nil {
		return report, err
	}
	captured := reply.Report.Manifest
	if captured.Version != 2 || captured.Database != manifest.Database || captured.Role != manifest.Role ||
		captured.Revision != manifest.Revision || captured.SchemaGeneration != manifest.SchemaGeneration ||
		!slices.Equal(captured.Relations, manifest.Relations) || !slices.Equal(captured.KeyReferences, manifest.KeyReferences) {
		return report, errors.New("tree capture manifest differs from admitted state")
	}
	return publishTreeRuntimeArchive(ctx, plan.dataRoot, plan.tmpRoot, reply.Scratch, "archive.tar", plan.output,
		reply.Report.SHA256, plan.nodeID, plan.archiveLimit, plan.safetyBytes)
}

func treeCaptureOfflineFact(plan treeRuntimeBackupPlan, fact RuntimeFact) ([]recovery.Relation, error) {
	if fact.NodeID != plan.nodeID || fact.Role != "Master" || fact.Database.Role != fact.Role ||
		fact.Database.SchemaGeneration != migrations.Generation || !fact.NativeMaintenance ||
		fact.Database.LogicalIdle || fact.Database.Pending["sealed_tree_unrecoverable"] != 1 {
		return nil, errors.New("tree capture requires the existing fenced SQLite Master")
	}
	for name, count := range fact.Database.Pending {
		if name != "sealed_tree_unrecoverable" && count != 0 {
			return nil, errors.New("unfinished native work blocks tree capture")
		}
	}
	relations := make([]recovery.Relation, 0, len(fact.Nodes))
	seen := map[string]bool{}
	for _, node := range fact.Nodes {
		if node.State == "revoked" {
			continue
		}
		decoded, e := hex.DecodeString(node.NodeID)
		if e != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != node.NodeID || node.NodeID == fact.NodeID ||
			seen[node.NodeID] || node.State != "active" || node.Direction != "downstream" || node.Protocol != 2 {
			return nil, errors.New("unsettled Owner relationship blocks tree capture")
		}
		seen[node.NodeID] = true
		relations = append(relations, recovery.Relation{NodeID: node.NodeID, Direction: node.Direction, State: node.State, Protocol: node.Protocol})
	}
	if len(relations) > recovery.MaxSetMembers {
		return nil, errors.New("tree capture Owner roster exceeds archive limit")
	}
	sort.Slice(relations, func(i, j int) bool { return relations[i].NodeID < relations[j].NodeID })
	return relations, nil
}

func (d *Deployment) treeCaptureStateSources(ctx context.Context, receipt Receipt, cfg Config, plan treeRuntimeBackupPlan, workspace *os.Root, pins map[string]os.FileInfo) ([]recovery.Root, error) {
	for _, name := range append([]string{ReceiptFile, ImagesFile, ".env"}, d.Files...) {
		if filepath.Base(name) != name || name == "." || name == ".." {
			return nil, errors.New("tree capture configuration filename is invalid")
		}
		source := filepath.Join(d.Directory, name)
		info, err := os.Lstat(source)
		if os.IsNotExist(err) && name == ".env" {
			pins[source] = nil
			continue
		}
		if err != nil {
			return nil, err
		}
		content, err := readRegular(source, 1<<20)
		current, currentErr := os.Lstat(source)
		if err != nil || currentErr != nil || len(content) > 1<<20 || !sameTreeRuntimeFile(info, current) {
			return nil, errors.New("tree capture configuration changed")
		}
		target, err := workspace.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		n, err := target.Write(content)
		if err == nil && n != len(content) {
			err = io.ErrShortWrite
		}
		clear(content)
		if err = errors.Join(err, target.Close()); err != nil {
			return nil, err
		}
		pins[source] = info
	}
	sources := []recovery.Root{{Class: "deployment", Directory: workspace.Name()}}
	roots := map[string]string{}
	mounted := map[string]bool{}
	stateClasses := map[string]bool{"redis_data": true, "certificate_state": true, "certificate_published": true}
	for name, service := range cfg.Services {
		if focHostInstaller(name, service) {
			continue
		}
		for _, mount := range service.Volumes {
			if mount.Type == "volume" {
				mounted[mount.Source] = true
			} else if class := recoveredMountClass(name, mount.Target); mount.Type == "bind" && stateClasses[class] {
				if !receipt.Recovered || filepath.Clean(mount.Source) != filepath.Join(filepath.Dir(d.Directory), class) ||
					roots[class] != "" && roots[class] != mount.Source {
					return nil, errors.New("tree capture state bind differs from receipt")
				}
				roots[class] = mount.Source
			}
		}
	}
	for class, volume := range cfg.Volumes {
		if !stateClasses[class] || receipt.Recovered && !mounted[class] {
			continue
		}
		if roots[class] != "" || volume.External {
			return nil, errors.New("tree capture state volume is ambiguous or external")
		}
		root, err := d.volumeRoot(ctx, volume.Name)
		if err != nil {
			return nil, err
		}
		roots[class] = root
	}
	for class, root := range roots {
		for _, other := range []string{plan.dataRoot, plan.secretsRoot, plan.tmpRoot, workspace.Name()} {
			if treePathsOverlap(root, other) {
				return nil, errors.New("tree capture state roots overlap")
			}
		}
		sources = append(sources, recovery.Root{Class: class, Directory: root})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Class < sources[j].Class })
	return sources, nil
}

func treeCaptureCreateArgs(plan treeRuntimeBackupPlan, name, nonce string) []string {
	return []string{"container", "create", "--interactive", "--name", name, "--label", treeCaptureLabel + "=" + nonce,
		"--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--pids-limit=32", "--memory=128m", "--memory-swap=128m", "--cpus=0.10",
		"--user", strconv.FormatUint(uint64(plan.runtimeUID), 10) + ":" + strconv.FormatUint(uint64(plan.runtimeGID), 10),
		// Existing maintenance lock files and SQLite BEGIN IMMEDIATE require
		// the pinned data bind writable. The runtime captures under its leases.
		"--mount", "type=bind,src=" + plan.dataRoot + ",dst=/fc-tree-data",
		"--mount", "type=bind,src=" + plan.secretsRoot + ",dst=/fc-tree-secrets,readonly",
		"--mount", "type=bind,src=" + plan.tmpRoot + ",dst=/fc-tree-tmp",
		"--entrypoint=/app/frontiercloud", plan.webImage, "tree-backup-capture"}
}

type treeCaptureChild struct {
	ID       string
	Status   string
	ExitCode int
}

func (d *Deployment) treeCaptureContainer(ctx context.Context, plan treeRuntimeBackupPlan, name, nonce string) (treeCaptureChild, error) {
	return d.treeRuntimeContainer(ctx, plan.webImage, name, nonce, treeCaptureLabel, "tree-backup-capture")
}

func (d *Deployment) treeRuntimeContainer(ctx context.Context, imageRef, name, nonce, labelKey string, command ...string) (treeCaptureChild, error) {
	var empty treeCaptureChild
	raw, err := d.Runner.Run(ctx, "docker", "container", "ls", "--all", "--no-trunc", "--filter", "name=^/"+name+"$", "--format", "{{.ID}}")
	if err != nil {
		return empty, err
	}
	id := strings.TrimSpace(string(raw))
	if id == "" {
		return empty, nil
	}
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != id {
		return empty, errors.New("tree capture child inventory is ambiguous")
	}
	raw, err = d.Runner.Run(ctx, "docker", "container", "inspect", "--format",
		"{{json .Id}} {{json .Name}} {{json .Config.Image}} {{json .Path}} {{json .Args}} {{json (index .Config.Labels \""+labelKey+"\")}} {{json .State.Status}} {{json .State.ExitCode}}", id)
	if err != nil {
		return empty, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	var child treeCaptureChild
	var observedName, image, executable, label string
	var args []string
	for _, value := range []any{&child.ID, &observedName, &image, &executable, &args, &label, &child.Status, &child.ExitCode} {
		if decoder.Decode(value) != nil {
			return empty, errors.New("tree capture child proof is invalid")
		}
	}
	if decoder.Decode(new(any)) != io.EOF || child.ID != id || observedName != "/"+name || image != imageRef ||
		executable != "/app/frontiercloud" || !slices.Equal(args, command) || label != nonce {
		return empty, errors.New("tree capture child does not match its private identity")
	}
	return child, nil
}

func (d *Deployment) removeTreeCaptureContainer(ctx context.Context, plan treeRuntimeBackupPlan, name, nonce string) error {
	child, err := d.treeCaptureContainer(ctx, plan, name, nonce)
	if err != nil || child.ID == "" {
		return err
	}
	if _, err = d.Runner.Run(ctx, "docker", "container", "rm", "--force", child.ID); err != nil {
		return errors.New("private tree capture child cleanup failed")
	}
	return nil
}

func removeTreeCaptureDirectory(root *os.Root, name string, pinned os.FileInfo) error {
	if pinned == nil {
		return nil
	}
	current, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !sameTreeRuntimeDirectory(pinned, current) {
		return errors.New("private tree capture directory changed before cleanup")
	}
	if err = root.RemoveAll(name); err != nil {
		return err
	}
	return fsutil.SyncDirectory(root, ".")
}
