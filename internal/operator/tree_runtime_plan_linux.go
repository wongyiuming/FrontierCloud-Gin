//go:build linux

package operator

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

type treeRuntimeBackupPlan struct {
	dataRoot, secretsRoot, tmpRoot, output    string
	runtimeUID, runtimeGID                    uint32
	archiveLimit, safetyBytes, stagingLimit   uint64
	receiptSelection, webImage, nodeID, scope string
}

// treeBackupRuntimePreflight is read-only. It uses the existing validated
// receipt and actual local volume ownership; it neither starts a backup nor
// authorizes a restored site. Unsupported UID mappings deliberately fail.
func (d *Deployment) treeBackupRuntimePreflight(ctx context.Context, receipt Receipt, output string) (treeRuntimeBackupPlan, error) {
	return d.treeBackupRuntimePreflightScope(ctx, receipt, output, "deployment")
}

func (d *Deployment) treeBackupRuntimePreflightScope(ctx context.Context, receipt Receipt, output, scope string) (treeRuntimeBackupPlan, error) {
	var p treeRuntimeBackupPlan
	if ctx == nil || receipt.Role != "master" || receipt.Database != "sqlite" || receipt.State != "ready" || scope != "deployment" && scope != recovery.UpgradeStateScope {
		return p, errors.New("tree backup requires a ready SQLite Master")
	}
	p.scope = scope
	cfg, err := d.ValidateReceipt(ctx, receipt)
	if err != nil {
		return p, err
	}
	web, ok := cfg.Services["web"]
	if !ok || web.Image == "" || receipt.ServiceImages["web"] != web.Image {
		return p, errors.New("tree backup web image is not receipt-bound")
	}
	var runtimeUser string
	if json.Unmarshal(web.Execution["user"], &runtimeUser) != nil {
		return p, errors.New("tree backup requires an explicit numeric runtime user")
	}
	parts := strings.Split(runtimeUser, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return p, errors.New("tree backup requires numeric uid:gid")
	}
	uid, e1 := strconv.ParseUint(parts[0], 10, 32)
	gid, e2 := strconv.ParseUint(parts[1], 10, 32)
	if e1 != nil || e2 != nil || strconv.FormatUint(uid, 10) != parts[0] || strconv.FormatUint(gid, 10) != parts[1] {
		return p, errors.New("invalid numeric runtime identity")
	}
	if raw, exists := web.Execution["userns_mode"]; exists {
		var mode string
		if json.Unmarshal(raw, &mode) != nil || mode != "" && mode != "host" {
			return p, errors.New("unsupported web user namespace")
		}
	}
	if err = d.requireTreeLocalDocker(ctx); err != nil {
		return p, err
	}
	data, err := upgradeDataRoot(cfg)
	if err != nil {
		return p, err
	}
	rootEnv, dbEnv := web.Environment["DATA_ROOT"], web.Environment["SQLITE_PATH"]
	if !path.IsAbs(rootEnv) || path.Clean(rootEnv) != rootEnv || !path.IsAbs(dbEnv) || path.Clean(dbEnv) != dbEnv || !strings.HasPrefix(dbEnv, rootEnv+"/") {
		return p, errors.New("SQLite is outside the recorded DATA_ROOT")
	}
	info, err := os.Lstat(data)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return p, errors.New("unsafe data root")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(uid) {
		return p, errors.New("data root and receipt runtime UID differ")
	}
	secretEnv := web.Environment["SECRETS_DIR"]
	if !path.IsAbs(secretEnv) || path.Clean(secretEnv) != secretEnv {
		return p, errors.New("invalid runtime secrets location")
	}
	var secretMount, tmpMount *Mount
	for _, mount := range web.Volumes {
		if mount.Target == secretEnv {
			if secretMount != nil {
				return p, errors.New("ambiguous secrets mount")
			}
			v := mount
			secretMount = &v
		}
		if mount.Target == "/tmp" {
			if tmpMount != nil {
				return p, errors.New("ambiguous runtime scratch mount")
			}
			v := mount
			tmpMount = &v
		}
	}
	if secretMount == nil || tmpMount == nil || tmpMount.Type != "volume" || tmpMount.ReadOnly {
		return p, errors.New("required private runtime mounts unavailable")
	}
	tmpVolume, ok := cfg.Volumes[tmpMount.Source]
	if !ok || tmpVolume.External {
		return p, errors.New("runtime scratch volume unavailable")
	}
	tmpRoot, err := d.volumeRoot(ctx, tmpVolume.Name)
	if err != nil {
		return p, err
	}
	var secretRoot string
	if secretMount.Type == "volume" {
		v, found := cfg.Volumes[secretMount.Source]
		if !found || v.External {
			return p, errors.New("secrets volume unavailable")
		}
		secretRoot, err = d.volumeRoot(ctx, v.Name)
	} else if secretMount.Type == "bind" && receipt.Recovered && recoveredMountClass("web", secretMount.Target) == "runtime_secrets" && filepath.Clean(secretMount.Source) == filepath.Join(filepath.Dir(d.Directory), "runtime_secrets") {
		secretRoot = secretMount.Source
	} else {
		return p, errors.New("secrets mount is not the recorded private root")
	}
	if err != nil {
		return p, err
	}
	secInfo, err := os.Lstat(secretRoot)
	if err != nil || !secInfo.IsDir() || secInfo.Mode()&os.ModeSymlink != 0 || secInfo.Mode().Perm() != 0700 {
		return p, errors.New("unsafe private secret root")
	}
	secStat, ok := secInfo.Sys().(*syscall.Stat_t)
	if !ok || secStat.Uid != uint32(uid) {
		return p, errors.New("secret root and receipt runtime UID differ")
	}
	secretDir, e := os.OpenRoot(secretRoot)
	if e != nil {
		return p, e
	}
	defer secretDir.Close()
	openedSecret, e := secretDir.Stat(".")
	if e != nil || !sameTreeRuntimeDirectory(secInfo, openedSecret) {
		return p, errors.New("secret root changed")
	}
	keyPins := map[string]os.FileInfo{}
	for _, name := range []string{"tree-master.key", "node-vault.key"} {
		before, e := secretDir.Lstat(name)
		if e != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
			return p, errors.New("required private tree key is unsafe")
		}
		keyStat, ok := before.Sys().(*syscall.Stat_t)
		if !ok || keyStat.Uid != uint32(uid) || keyStat.Nlink != 1 || name == "tree-master.key" && before.Size() != 32 || name == "node-vault.key" && (before.Size() < 1 || before.Size() > 128) {
			return p, errors.New("required private tree key has unexpected identity")
		}
		keyPins[name] = before
		f, e := secretDir.Open(name)
		if e != nil {
			return p, e
		}
		opened, e := f.Stat()
		f.Close()
		if e != nil || !os.SameFile(before, opened) {
			return p, errors.New("private tree key changed")
		}
	}
	dataDir, e := os.OpenRoot(data)
	if e != nil {
		return p, e
	}
	defer dataDir.Close()
	openedData, e := dataDir.Stat(".")
	if e != nil || !sameTreeRuntimeDirectory(info, openedData) {
		return p, errors.New("data root changed")
	}
	treeInfo, e := dataDir.Lstat(sealedtree.MasterFenceDirectory)
	if e != nil || !treeInfo.IsDir() || treeInfo.Mode()&os.ModeSymlink != 0 || treeInfo.Mode().Perm()&0077 != 0 {
		return p, errors.New("Master tree fence directory is unsafe")
	}
	treeStat, ok := treeInfo.Sys().(*syscall.Stat_t)
	if !ok || treeStat.Uid != uint32(uid) {
		return p, errors.New("Master tree fence directory has unexpected owner")
	}
	treeDir, e := dataDir.OpenRoot(sealedtree.MasterFenceDirectory)
	if e != nil {
		return p, errors.New("Master tree fence directory unavailable")
	}
	defer treeDir.Close()
	openedTree, e := treeDir.Stat(".")
	if e != nil || !sameTreeRuntimeDirectory(treeInfo, openedTree) {
		return p, errors.New("Master tree fence directory changed")
	}
	treePins := map[string]os.FileInfo{}
	for _, path := range sealedtree.MasterStatePaths() {
		name := filepath.Base(path)
		before, e := treeDir.Lstat(name)
		if e != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
			return p, errors.New("Master tree fence state is unsafe")
		}
		st, ok := before.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uint32(uid) || st.Nlink != 1 || before.Size() <= 0 || before.Size() > 4096 {
			return p, errors.New("Master tree fence state has unexpected identity")
		}
		f, e := treeDir.Open(name)
		if e != nil {
			return p, e
		}
		actual, e := f.Stat()
		f.Close()
		if e != nil || !os.SameFile(before, actual) {
			return p, errors.New("Master tree fence state changed")
		}
		treePins[name] = before
	}
	var databasePin os.FileInfo
	relative := strings.TrimPrefix(dbEnv, rootEnv+"/")
	components := strings.Split(relative, "/")
	for i := range components {
		name := strings.Join(components[:i+1], "/")
		info, e := dataDir.Lstat(name)
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return p, errors.New("SQLite backup path is unsafe")
		}
		if i < len(components)-1 {
			if !info.IsDir() {
				return p, errors.New("SQLite backup path is unsafe")
			}
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uint32(uid) || st.Nlink != 1 {
			return p, errors.New("SQLite backup file identity is unsafe")
		}
		databasePin = info
		f, e := dataDir.Open(name)
		if e != nil {
			return p, e
		}
		actual, e := f.Stat()
		f.Close()
		if e != nil || !os.SameFile(info, actual) {
			return p, errors.New("SQLite backup file changed")
		}
	}
	tmpInfo, err := os.Lstat(tmpRoot)
	if err != nil || !tmpInfo.IsDir() || tmpInfo.Mode()&os.ModeSymlink != 0 {
		return p, errors.New("unsafe runtime scratch root")
	}
	tmpStat, ok := tmpInfo.Sys().(*syscall.Stat_t)
	ownerWritable := ok && tmpStat.Uid == uint32(uid) && tmpInfo.Mode().Perm()&0700 == 0700 && (tmpInfo.Mode().Perm()&0022 == 0 || tmpInfo.Mode()&os.ModeSticky != 0)
	worldSticky := ok && tmpInfo.Mode()&os.ModeSticky != 0 && tmpInfo.Mode().Perm()&0003 == 0003
	if !ownerWritable && !worldSticky {
		return p, errors.New("runtime user cannot safely create private scratch")
	}
	// Staging must never create files inside data or secrets, including via
	// aliased/nested host mounts selected by an otherwise valid receipt.
	roots := []string{data, secretRoot, tmpRoot}
	infos := []os.FileInfo{info, secInfo, tmpInfo}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if os.SameFile(infos[i], infos[j]) || treePathsOverlap(roots[i], roots[j]) {
				return p, errors.New("tree runtime roots overlap")
			}
		}
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return p, err
	}
	if _, e := os.Lstat(output); !os.IsNotExist(e) {
		return p, errors.New("tree backup output already exists")
	}
	parent := filepath.Dir(output)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm() != 0700 {
		return p, errors.New("tree backup output parent must be private")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != uint32(os.Geteuid()) {
		return p, errors.New("tree backup output parent has unexpected owner")
	}
	for _, root := range []string{data, secretRoot, tmpRoot} {
		rel, e := filepath.Rel(root, output)
		if e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return p, errors.New("tree backup output overlaps a source root")
		}
	}
	// This is only a candidate; it is checked again under the eventual native
	// lease. Never promote the configured Master role into a NodeID claim.
	fact, err := d.runtimeFact(ctx)
	if err != nil || fact.Role != "Master" {
		return p, errors.New("tree backup requires an observed Master identity")
	}
	nodeBytes, nodeErr := hex.DecodeString(fact.NodeID)
	if nodeErr != nil || len(nodeBytes) != 16 || hex.EncodeToString(nodeBytes) != fact.NodeID {
		return p, errors.New("tree backup Master identity is invalid")
	}
	var treeSelection []string
	if scope == recovery.UpgradeStateScope {
		treeSelection = sealedtree.MasterStatePaths()
	}
	cap, err := d.backupCapacityScopeWithTree(ctx, receipt, output, "", scope, treeSelection, true)
	if err != nil || !cap.Fits {
		return p, errors.New("tree backup capacity unavailable")
	}
	// Reserve 8 KiB for the extra authenticated v2 manifest and tar padding.
	if cap.ManifestBytes > uint64(recovery.MaxManifest)-8192 {
		return p, errors.New("tree recovery manifest exceeds format limit")
	}
	if cap.ArchiveBytes > math.MaxUint64-8192 || cap.RequiredBytes > math.MaxUint64-8192 {
		return p, errors.New("tree backup size overflow")
	}
	limit := cap.ArchiveBytes + 8192
	// Runtime staging preserves bytes of all non-data/non-secret classes in
	// addition to the staged archive. Account conservatively for one filesystem
	// block per file/directory, without assuming sparse allocation.
	var fsstat syscall.Statfs_t
	if e := syscall.Statfs(tmpRoot, &fsstat); e != nil || fsstat.Bsize <= 0 || fsstat.Bsize > 1<<20 {
		return p, errors.New("runtime scratch block size unavailable")
	}
	block := uint64(fsstat.Bsize)
	if cap.treeStageEntries > math.MaxUint64/block || cap.treeStageBytes > math.MaxUint64-cap.treeStageEntries*block {
		return p, errors.New("tree staging size overflow")
	}
	staging := cap.treeStageBytes + cap.treeStageEntries*block
	outputNeed := cap.RequiredBytes + 8192
	outputFree, e := diskFree(parent)
	if e != nil {
		return p, errors.New("private output capacity unavailable")
	}
	tmpFree := outputFree
	if tmpStat.Dev != parentStat.Dev {
		tmpFree, e = diskFree(tmpRoot)
		if e != nil {
			return p, errors.New("runtime scratch capacity unavailable")
		}
	}
	if !treeBackupCapacityFits(outputFree, tmpFree, tmpStat.Dev == parentStat.Dev, outputNeed, limit, staging, cap.SafetyBytes) {
		return p, errors.New("insufficient private backup capacity")
	}

	// A receipt binds the configured sources, while this short-lived,
	// networkless instance proves how the selected image and daemon actually
	// see those exact host inodes under the configured numeric runtime identity.
	if err = d.proveTreeBackupRuntime(ctx, web.Image, uint32(uid), uint32(gid), data, secretRoot, tmpRoot, info, secInfo, tmpInfo); err != nil {
		return p, err
	}
	if _, err = d.ValidateReceipt(ctx, receipt); err != nil {
		return p, err
	}
	// A plan is still only a candidate, but reject changes even during this
	// inspection. The eventual fenced execution must pin and revalidate again.
	dataNow, e := os.Lstat(data)
	if e != nil || !sameTreeRuntimeDirectory(info, dataNow) {
		return p, errors.New("data root changed during plan")
	}
	secretNow, e := os.Lstat(secretRoot)
	if e != nil || !sameTreeRuntimeDirectory(secInfo, secretNow) {
		return p, errors.New("secret root changed during plan")
	}
	tmpNow, e := os.Lstat(tmpRoot)
	if e != nil || !sameTreeRuntimeDirectory(tmpInfo, tmpNow) {
		return p, errors.New("scratch root changed during plan")
	}
	parentNow, e := os.Lstat(parent)
	if e != nil || !sameTreeRuntimeDirectory(parentInfo, parentNow) {
		return p, errors.New("output parent changed during plan")
	}
	databaseNow, e := dataDir.Lstat(relative)
	if e != nil || !sameTreeRuntimeFile(databasePin, databaseNow) {
		return p, errors.New("SQLite file changed during plan")
	}
	for name, before := range keyPins {
		current, e := secretDir.Lstat(name)
		if e != nil || !sameTreeRuntimeFile(before, current) {
			return p, errors.New("private tree key changed during plan")
		}
	}
	treeNow, e := dataDir.Lstat(sealedtree.MasterFenceDirectory)
	if e != nil || !sameTreeRuntimeDirectory(treeInfo, treeNow) {
		return p, errors.New("Master tree fence directory changed during plan")
	}
	for name, before := range treePins {
		current, e := treeDir.Lstat(name)
		if e != nil || !sameTreeRuntimeFile(before, current) {
			return p, errors.New("Master tree fence state changed during plan")
		}
	}
	if _, e = os.Lstat(output); !os.IsNotExist(e) {
		return p, errors.New("tree backup output appeared during plan")
	}
	return treeRuntimeBackupPlan{dataRoot: data, secretsRoot: secretRoot, tmpRoot: tmpRoot, output: output, runtimeUID: uint32(uid), runtimeGID: uint32(gid), archiveLimit: limit, safetyBytes: cap.SafetyBytes, stagingLimit: cap.treeStageBytes, receiptSelection: receipt.SelectionHash, webImage: web.Image, nodeID: fact.NodeID, scope: scope}, nil
}

func (d *Deployment) requireTreeLocalDocker(ctx context.Context) error {
	endpointRaw, err := d.Runner.Run(ctx, "docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}")
	var endpoint string
	if err != nil || json.Unmarshal(endpointRaw, &endpoint) != nil || !strings.HasPrefix(endpoint, "unix://") || os.Getenv("DOCKER_HOST") != "" && !strings.HasPrefix(os.Getenv("DOCKER_HOST"), "unix://") {
		return errors.New("tree state operations require local Docker")
	}
	optionsRaw, err := d.Runner.Run(ctx, "docker", "info", "--format", "{{json .SecurityOptions}}")
	var options []string
	if err != nil || json.Unmarshal(optionsRaw, &options) != nil || options == nil {
		return errors.New("Docker user namespace cannot be verified")
	}
	for _, v := range options {
		v = strings.ToLower(v)
		if strings.Contains(v, "userns") || strings.Contains(v, "rootless") {
			return errors.New("remapped or rootless Docker is not supported for tree state operations")
		}
	}
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil || !treeIdentityUIDMap(string(uidMap)) {
		return errors.New("foc user namespace cannot be verified")
	}
	return nil
}

func treeIdentityUIDMap(raw string) bool {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) != 1 {
		return false
	}
	fields := strings.Fields(lines[0])
	if len(fields) != 3 {
		return false
	}
	return fields[0] == "0" && fields[1] == "0" && fields[2] == "4294967295"
}

// existingRequired already contains the normal output safety allowance.
// When both files share a filesystem it must also fit the staged archive.
func treeBackupCapacityFits(outputFree, tmpFree uint64, same bool, existingRequired, archive, staging, safety uint64) bool {
	if archive > math.MaxUint64-staging {
		return false
	}
	scratch := archive + staging
	if same {
		return existingRequired <= math.MaxUint64-scratch && outputFree >= existingRequired+scratch
	}
	return scratch <= math.MaxUint64-safety && outputFree >= existingRequired && tmpFree >= scratch+safety
}

func treeRuntimeMount(info os.FileInfo) (runtimefacts.TreeBackupMount, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() {
		return runtimefacts.TreeBackupMount{}, errors.New("runtime mount identity unavailable")
	}
	return runtimefacts.TreeBackupMount{Device: uint64(st.Dev), Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode}, nil
}
func (d *Deployment) proveTreeBackupRuntime(ctx context.Context, image string, uid, gid uint32, data, secrets, tmp string, dataInfo, secretInfo, tmpInfo os.FileInfo) error {
	i := strings.LastIndex(image, "@sha256:")
	if i <= 0 || len(image[i+8:]) != 64 {
		return errors.New("tree runtime image is not digest-pinned")
	}
	imageDigest, e := hex.DecodeString(image[i+8:])
	if e != nil || len(imageDigest) != 32 || hex.EncodeToString(imageDigest) != image[i+8:] {
		return errors.New("tree runtime image is not digest-pinned")
	}
	for _, p := range []string{data, secrets, tmp} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, ",\r\n\x00") {
			return errors.New("unsupported tree runtime mount path")
		}
	}
	expectedData, e := treeRuntimeMount(dataInfo)
	if e != nil {
		return e
	}
	expectedSecrets, e := treeRuntimeMount(secretInfo)
	if e != nil {
		return e
	}
	expectedTmp, e := treeRuntimeMount(tmpInfo)
	if e != nil {
		return e
	}
	var random [32]byte
	if _, e = rand.Read(random[:]); e != nil {
		return e
	}
	nonce := hex.EncodeToString(random[:])
	args := []string{"run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=32", "--memory=128m", "--memory-swap=128m", "--cpus=0.10", "--user", strconv.FormatUint(uint64(uid), 10) + ":" + strconv.FormatUint(uint64(gid), 10), "--mount", "type=bind,src=" + data + ",dst=/fc-tree-data,readonly", "--mount", "type=bind,src=" + secrets + ",dst=/fc-tree-secrets,readonly", "--mount", "type=bind,src=" + tmp + ",dst=/fc-tree-tmp,readonly", "--entrypoint=/app/frontiercloud", image, "tree-backup-runtime-inspect", nonce}
	raw, e := d.Runner.Run(ctx, "docker", args...)
	if e != nil || len(raw) > 4096 {
		return errors.New("tree runtime inspection failed")
	}
	var proof runtimefacts.TreeBackupRuntime
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&proof) != nil || dec.Decode(new(any)) != io.EOF || proof.Nonce != nonce || proof.UID != uid || proof.GID != gid || !treeIdentityUIDMap(proof.UIDMap) || proof.Data != expectedData || proof.Secrets != expectedSecrets || proof.Scratch != expectedTmp {
		return errors.New("tree runtime identity or mount mismatch")
	}
	return nil
}

func treePathsOverlap(a, b string) bool {
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		rel, e := filepath.Rel(pair[0], pair[1])
		if e != nil {
			return true
		}
		if rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
