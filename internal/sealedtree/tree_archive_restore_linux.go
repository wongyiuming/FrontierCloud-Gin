//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"golang.org/x/sys/unix"
)

const treeRebindIntentName = MasterRebindIntentFile

type treeRebindIntent struct {
	Version                                                int `json:"version"`
	ArchiveSHA, EvidenceMAC, NodeID                        string
	DatabaseDevice, DatabaseInode, FenceDevice, FenceInode uint64
	MAC                                                    string
}

func treeRebindIntentMAC(secret []byte, v treeRebindIntent) (string, error) {
	v.MAC = ""
	raw, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	defer clear(raw)
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("frontiercloud:tree-rebind-intent:v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func privateInode(root *os.Root, name string) (uint64, uint64, error) {
	info, e := root.Lstat(name)
	if e != nil || !privateBindingFile(info) {
		return 0, 0, ErrFenceRequired
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return 0, 0, ErrFenceRequired
	}
	f, e := root.Open(name)
	if e != nil {
		return 0, 0, e
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return 0, 0, ErrFenceRequired
	}
	return uint64(stat.Dev), stat.Ino, nil
}

func verifyArchivedFile(ctx context.Context, root *os.Root, name, archiveName string, report recovery.Report) error {
	var expected *recovery.Entry
	for i := range report.Manifest.Files {
		if report.Manifest.Files[i].Path == archiveName {
			expected = &report.Manifest.Files[i]
			break
		}
	}
	if expected == nil {
		return ErrFenceRequired
	}
	info, e := root.Lstat(name)
	if e != nil || !info.Mode().IsRegular() || info.Size() != expected.Bytes {
		return ErrFenceRequired
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || int64(info.Mode().Perm()) != expected.Mode || int(stat.Uid) != expected.UID || int(stat.Gid) != expected.GID {
		return ErrFenceRequired
	}
	unchanged := func(current os.FileInfo) bool {
		if current == nil || !os.SameFile(info, current) || current.Size() != info.Size() || current.Mode() != info.Mode() || !current.ModTime().Equal(info.ModTime()) {
			return false
		}
		currentStat, ok := current.Sys().(*syscall.Stat_t)
		return ok && currentStat.Ctim == stat.Ctim
	}
	f, e := root.Open(name)
	if e != nil {
		return e
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !unchanged(actual) {
		return ErrFenceRequired
	}
	h := sha256.New()
	n, e := io.CopyBuffer(h, io.LimitReader(&contextReader{ctx: ctx, r: f}, expected.Bytes+1), make([]byte, 64<<10))
	after, statErr := f.Stat()
	current, pathErr := root.Lstat(name)
	if e != nil || statErr != nil || pathErr != nil || n != expected.Bytes || !unchanged(after) || !unchanged(current) || hex.EncodeToString(h.Sum(nil)) != expected.SHA256 {
		return ErrFenceRequired
	}
	return nil
}

// RebindMasterTreeBackup binds only the fixed Master fence directory in an
// already extracted, verified private recovery target. It does not reconcile
// Owner data or authorize service startup.
func RebindMasterTreeBackup(ctx context.Context, gate *maintenance.Gate, archive, expectedSHA, restoredRoot, databaseRel, nodeID string) (bool, error) {
	return rebindVerifiedTreeBackup(ctx, gate, archive, expectedSHA, restoredRoot, databaseRel, MasterFenceDirectory, nodeID)
}

// rebindVerifiedTreeBackup is an unregistered recovery coordinator. It verifies
// the actual private archive against its independently retained checksum and
// its embedded authenticated source-fence evidence. The first attempt checks
// all extracted material and durably records a keyed inode-bound intent BEFORE
// the CAS. A crash retry accepts only that exact intent and the exact old/new
// generation/tag states. It neither validates remote Owner content nor opens
// maintenance; those are mandatory separate steps.
func rebindVerifiedTreeBackup(ctx context.Context, gate *maintenance.Gate, archive, expectedSHA, restoredRoot, databaseRel, fenceRel, nodeID string) (bool, error) {
	absolute, e := filepath.Abs(restoredRoot)
	if e != nil {
		return false, ErrInvalid
	}
	target := treeRecoveryTarget{material: absolute, data: filepath.Join(absolute, "data"), secrets: filepath.Join(absolute, "runtime_secrets")}
	return rebindTreeArchiveAt(ctx, gate, archive, expectedSHA, target, databaseRel, fenceRel, nodeID)
}

func rebindTreeArchiveAt(ctx context.Context, gate *maintenance.Gate, archive, expectedSHA string, target treeRecoveryTarget, databaseRel, fenceRel, nodeID string) (bool, error) {
	if ctx == nil || gate == nil || !hexID(expectedSHA) || !lowerHex(nodeID, 32) {
		return false, ErrInvalid
	}
	report, e := recovery.CheckTreeArchive(ctx, archive, expectedSHA)
	if e != nil || !report.Verified {
		return false, ErrFenceRequired
	}
	return rebindTreeManifestAt(ctx, gate, report, target, databaseRel, fenceRel, nodeID)
}

// A retained runtime receives a privately verified manifest from the host.
// Its report deliberately does not claim that the runtime has read the archive.
func rebindTreeManifestAt(ctx context.Context, gate *maintenance.Gate, report recovery.Report, target treeRecoveryTarget, databaseRel, fenceRel, nodeID string) (bool, error) {
	if ctx == nil || gate == nil || !hexID(report.SHA256) || !lowerHex(nodeID, 32) {
		return false, ErrInvalid
	}
	for _, p := range []string{databaseRel, fenceRel} {
		if p == "" || filepath.IsAbs(p) || filepath.Clean(p) != p || p == "." || p == ".." || strings.HasPrefix(p, ".."+string(filepath.Separator)) {
			return false, ErrInvalid
		}
	}
	if report.Manifest.NodeID != nodeID || target.retained && report.Manifest.Scope != recovery.UpgradeStateScope {
		return false, ErrFenceRequired
	}
	var evidence fenceRecoveryEvidence
	decoder := json.NewDecoder(bytes.NewReader(report.Manifest.TreeEvidence))
	decoder.DisallowUnknownFields()
	digest, digestErr := recovery.TreeManifestDigest(report.Manifest)
	if digestErr != nil || decoder.Decode(&evidence) != nil || decoder.Decode(new(any)) != io.EOF || evidence.ManifestSHA != digest || evidence.NodeID != nodeID {
		return false, ErrFenceRequired
	}
	dataRoot, secretPath := target.data, target.secrets
	data, e := os.OpenRoot(dataRoot)
	if e != nil {
		return false, e
	}
	defer data.Close()
	keys, e := os.OpenRoot(secretPath)
	if e != nil {
		return false, e
	}
	defer keys.Close()
	checkDataDirectory := checkPrivateDirectory
	if target.retained && target.material == "" {
		checkDataDirectory = checkRetainedTreeDataDirectory
	}
	if checkDataDirectory(data) != nil || checkPrivateDirectory(keys) != nil {
		return false, ErrFenceRequired
	}
	if verifyArchivedFile(ctx, keys, treeKeyFile, "runtime_secrets/"+treeKeyFile, report) != nil || verifyArchivedFile(ctx, keys, "node-vault.key", "runtime_secrets/node-vault.key", report) != nil {
		return false, ErrFenceRequired
	}
	secret, e := OpenTreeSecretFile(keys)
	if e != nil {
		return false, e
	}
	defer clear(secret)
	outer, outerErr := fenceRecoveryOuterMAC(secret, evidence)
	if outerErr != nil || !hmac.Equal([]byte(outer), []byte(evidence.RecoveryMAC)) {
		return false, ErrFenceRequired
	}
	nodeVault, e := vault.OpenExisting(secretPath)
	if e != nil {
		return false, e
	}
	fenceDir := filepath.Join(dataRoot, fenceRel)
	fence, e := os.OpenRoot(fenceDir)
	if e != nil {
		return false, e
	}
	defer fence.Close()
	dbPath := filepath.Join(dataRoot, databaseRel)
	expectedDB := "data/" + filepath.ToSlash(databaseRel)
	expectedFence := "data/" + filepath.ToSlash(filepath.Join(fenceRel, treeFenceFile))
	expectedBinding := "data/" + filepath.ToSlash(filepath.Join(fenceRel, existingMasterBindingFile))
	if !treeArchiveContains(report, expectedDB) || !treeArchiveContains(report, expectedFence) || !treeArchiveContains(report, expectedBinding) {
		return false, ErrFenceRequired
	}
	var newIntent *treeRebindIntent
	verifyGuard := func(c context.Context) error {
		if target.guard != nil {
			return target.guard(c)
		}
		return nil
	}
	prepare := func(c context.Context, check func() error) error {
		if check() != nil {
			return ErrFenceRequired
		}
		if err := verifyGuard(c); err != nil {
			return err
		}
		dbDev, dbIno, e := privateInode(data, databaseRel)
		if e != nil {
			return e
		}
		fenceDev, fenceIno, e := privateInode(fence, treeFenceFile)
		if e != nil {
			return e
		}
		intent := treeRebindIntent{Version: 1, ArchiveSHA: report.SHA256, EvidenceMAC: evidence.MAC, NodeID: nodeID, DatabaseDevice: dbDev, DatabaseInode: dbIno, FenceDevice: fenceDev, FenceInode: fenceIno}
		intent.MAC, e = treeRebindIntentMAC(secret, intent)
		if e != nil {
			return e
		}
		info, e := data.Lstat(treeRebindIntentName)
		first := errors.Is(e, os.ErrNotExist)
		if target.retained {
			// SQLite may already have changed its own sidecars on a prior
			// attempt. The archive fence and binding must remain exact.
			if err := checkRetainedTreeSQLite(c, data, databaseRel, fenceRel, report, first); err != nil {
				return err
			}
		}
		if first {
			if target.material != "" {
				if e = recovery.CheckTreeMaterial(c, target.material, report); e != nil {
					return e
				}
			}
			newIntent = &intent
		} else {
			// A previous publication may have returned after linking but before
			// syncing the directory. A retry must establish durability before
			// it permits the fence transaction to advance.
			if e != nil {
				return e
			}
			if err := checkTreeRebindIntent(data, info, intent, true); err != nil {
				return err
			}
		}
		if check() != nil {
			return ErrFenceRequired
		}
		return verifyGuard(c)
	}
	sealIntent := func(c context.Context, check func() error) error {
		if check() != nil || c.Err() != nil {
			return ErrFenceRequired
		}
		if newIntent == nil {
			return verifyGuard(c)
		}
		dbDev, dbIno, e := privateInode(data, databaseRel)
		if e != nil {
			return e
		}
		fenceDev, fenceIno, e := privateInode(fence, treeFenceFile)
		if e != nil {
			return e
		}
		if dbDev != newIntent.DatabaseDevice || dbIno != newIntent.DatabaseInode || fenceDev != newIntent.FenceDevice || fenceIno != newIntent.FenceInode {
			return ErrFenceRequired
		}
		raw, e := json.Marshal(newIntent)
		if e != nil {
			return e
		}
		defer clear(raw)
		if e = publishTreeRebindIntent(c, data, raw, func() error {
			if check() != nil || c.Err() != nil {
				return ErrFenceRequired
			}
			dbDev, dbIno, err := privateInode(data, databaseRel)
			if err != nil || dbDev != newIntent.DatabaseDevice || dbIno != newIntent.DatabaseInode {
				return ErrFenceRequired
			}
			fenceDev, fenceIno, err := privateInode(fence, treeFenceFile)
			if err != nil || fenceDev != newIntent.FenceDevice || fenceIno != newIntent.FenceInode {
				return ErrFenceRequired
			}
			return check()
		}); e != nil {
			return e
		}
		return verifyGuard(c)
	}
	return rebindOfflineFencePrepared(ctx, gate, dataRoot, dbPath, fence, fenceDir, secret, nodeVault, nodeID, digest, evidence, prepare, sealIntent)
}

func checkTreeRebindIntent(data *os.Root, info os.FileInfo, expected treeRebindIntent, sync bool) error {
	if !privateBindingFile(info) || info.Size() < 1 || info.Size() > 4096 {
		return ErrFenceRequired
	}
	f, err := data.Open(treeRebindIntentName)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return ErrFenceRequired
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return ErrFenceRequired
	}
	defer clear(raw)
	var got treeRebindIntent
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&got) != nil || decoder.Decode(new(any)) != io.EOF || got != expected {
		return ErrFenceRequired
	}
	if sync {
		if err = f.Sync(); err != nil {
			return err
		}
		if err = fsutil.SyncDirectory(data, "."); err != nil {
			return err
		}
	}
	after, statErr := f.Stat()
	current, pathErr := data.Lstat(treeRebindIntentName)
	if statErr != nil || pathErr != nil || !privateBindingFile(current) ||
		!os.SameFile(opened, after) || !os.SameFile(opened, current) ||
		after.Size() != opened.Size() || current.Size() != opened.Size() ||
		!after.ModTime().Equal(opened.ModTime()) || !current.ModTime().Equal(opened.ModTime()) {
		return ErrFenceRequired
	}
	return nil
}

// publishTreeRebindIntent publishes only a completely written and synced
// intent. An anonymous inode leaves no partial named file after a crash before
// publication, while linkat cannot replace an existing intent. Filesystems or
// procfs configurations without this primitive fail closed.
func publishTreeRebindIntent(ctx context.Context, root *os.Root, raw []byte, check func() error) error {
	if ctx == nil || root == nil || check == nil || len(raw) == 0 || len(raw) > 4096 {
		return ErrFenceRequired
	}
	guard := func() error {
		if ctx.Err() != nil || check() != nil || ctx.Err() != nil {
			return ErrFenceRequired
		}
		return nil
	}
	if err := guard(); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), ".", unix.O_TMPFILE|unix.O_WRONLY|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "anonymous-tree-rebind-intent")
	if file == nil {
		_ = unix.Close(fd)
		return ErrFenceRequired
	}
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		return err
	}
	if n, writeErr := file.Write(raw); writeErr != nil {
		return writeErr
	} else if n != len(raw) {
		return io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = guard(); err != nil {
		return err
	}
	// The procfs reference names this open inode, not a caller-selected path.
	// Unlike AT_EMPTY_PATH, this does not require CAP_DAC_READ_SEARCH.
	proc := "/proc/self/fd/" + strconv.Itoa(fd)
	if err = unix.Linkat(unix.AT_FDCWD, proc, int(dir.Fd()), treeRebindIntentName, unix.AT_SYMLINK_FOLLOW); err != nil {
		return err
	}
	opened, statErr := file.Stat()
	named, nameErr := root.Lstat(treeRebindIntentName)
	if statErr != nil || nameErr != nil || !privateBindingFile(named) || !os.SameFile(opened, named) || named.Size() != int64(len(raw)) {
		return ErrFenceRequired
	}
	if err = dir.Sync(); err != nil {
		return err
	}
	return guard()
}
