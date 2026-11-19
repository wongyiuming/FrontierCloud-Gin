//go:build linux

package operator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
	"golang.org/x/sys/unix"
)

// treeRetainedInstall does not obtain locks or authorize an archive. Its
// caller holds the host operation and native/site leases and supplies a report
// from authenticated v2 verification. It never installs deployment metadata.
type treeRetainedInstall struct {
	database   string
	report     recovery.Report
	roots      map[string]string
	pins       map[string]os.FileInfo
	selectData []string
	entries    []recovery.Entry
	dirs       []recovery.Directory
	retained   string
}

type treeRetainedSnapshot struct {
	Version int               `json:"version"`
	Archive string            `json:"archive_sha256"`
	Roots   map[string]string `json:"roots"`
	Files   []recovery.Entry  `json:"files"`
}

const treeRetainedSnapshotName = ".tree-retained-snapshot.json"

func treeRetainedProtected(name string) bool {
	switch name {
	case maintenance.Marker, maintenance.TreeRecoveryHold, maintenance.OwnerImportHold,
		sitecontrol.Manual, sitecontrol.ForceOpen, sitecontrol.Lock,
		".native-runtime.lock", ".native-maintenance-control.lock", sealedtree.MasterRebindIntentFile:
		return true
	}
	return false
}

func prepareTreeRetainedInstall(ctx context.Context, cfg Config, receipt Receipt, roots map[string]string, report recovery.Report) (treeRetainedInstall, error) {
	var p treeRetainedInstall
	if ctx == nil || ctx.Err() != nil || !report.Verified || report.Manifest.Version != 2 ||
		report.Manifest.Role != "Master" || report.Manifest.Database != "sqlite" || report.Manifest.Scope != recovery.UpgradeStateScope ||
		receipt.Role != "master" || receipt.Database != "sqlite" || len(report.SHA256) != 64 {
		return p, recovery.ErrUnsafe
	}
	decoded, err := hex.DecodeString(report.SHA256)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != report.SHA256 {
		return p, recovery.ErrUnsafe
	}
	selection, err := upgradeStateSelection(cfg, receipt, false)
	if err != nil {
		return p, err
	}
	selection = append(selection, sealedtree.MasterStatePaths()...)
	dataRoot, err := upgradeDataRoot(cfg)
	if err != nil || filepath.Clean(dataRoot) != filepath.Clean(roots["data"]) {
		return p, recovery.ErrUnsafe
	}
	env := cfg.Services["web"].Environment
	data, db := path.Clean(env["DATA_ROOT"]), path.Clean(env["SQLITE_PATH"])
	if !path.IsAbs(data) || !strings.HasPrefix(db, data+"/") || db != env["SQLITE_PATH"] {
		return p, recovery.ErrUnsafe
	}
	p.database = strings.TrimPrefix(db, data+"/")
	p.report, p.selectData = report, selection
	p.roots, p.pins = map[string]string{}, map[string]os.FileInfo{}
	classes := map[string]bool{}
	for _, class := range report.Manifest.Classes {
		if classes[class] {
			return treeRetainedInstall{}, recovery.ErrUnsafe
		}
		classes[class] = true
		if class == "deployment" {
			continue
		}
		switch class {
		case "data", "runtime_secrets", "redis_data", "certificate_state", "certificate_published":
		default:
			return treeRetainedInstall{}, recovery.ErrUnsafe
		}
		dir := roots[class]
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
			return treeRetainedInstall{}, recovery.ErrUnsafe
		}
		info, e := os.Lstat(dir)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return treeRetainedInstall{}, recovery.ErrUnsafe
		}
		canonical, e := filepath.EvalSymlinks(dir)
		if e != nil || canonical != dir {
			return treeRetainedInstall{}, recovery.ErrUnsafe
		}
		for _, other := range p.roots {
			if treePathsOverlap(dir, other) {
				return treeRetainedInstall{}, recovery.ErrUnsafe
			}
		}
		p.roots[class], p.pins[class] = dir, info
	}
	if !classes["data"] || !classes["runtime_secrets"] {
		return treeRetainedInstall{}, recovery.ErrUnsafe
	}
	for class, dir := range roots {
		if class != "deployment" && dir != "" && !classes[class] {
			return treeRetainedInstall{}, errors.New("retained state class is absent from archive")
		}
	}
	found := map[string]bool{}
	for _, entry := range report.Manifest.Files {
		class, relative, ok := strings.Cut(entry.Path, "/")
		if !ok || !fs.ValidPath(entry.Path) || found[entry.Path] || !classes[class] {
			return treeRetainedInstall{}, recovery.ErrUnsafe
		}
		found[entry.Path] = true
		if class == "deployment" || class == "data" && treeRetainedProtected(relative) {
			continue
		}
		if class == "data" && !recovery.SelectedPath(selection, relative, false) {
			return treeRetainedInstall{}, recovery.ErrUnsafe
		}
		p.entries = append(p.entries, entry)
	}
	for _, required := range append([]string{"data/" + p.database, "runtime_secrets/tree-master.key", "runtime_secrets/node-vault.key"}, prefixTreeStatePaths()...) {
		if !found[required] {
			return treeRetainedInstall{}, recovery.ErrUnsafe
		}
	}
	for _, dir := range report.Manifest.Directories {
		class, relative, ok := strings.Cut(dir.Path, "/")
		if !classes[class] {
			return treeRetainedInstall{}, recovery.ErrUnsafe
		}
		if class == "deployment" {
			continue
		}
		if ok && class == "data" && !recovery.SelectedPath(selection, relative, true) {
			return treeRetainedInstall{}, recovery.ErrUnsafe
		}
		p.dirs = append(p.dirs, dir)
	}
	sort.Slice(p.dirs, func(i, j int) bool { return p.dirs[i].Path < p.dirs[j].Path })
	if err = p.checkRoots(); err != nil {
		return treeRetainedInstall{}, err
	}
	if err = checkRestoreDestinationCapacity(p.roots, p.entries, diskFree); err != nil {
		return treeRetainedInstall{}, err
	}
	return p, nil
}

func (p *treeRetainedInstall) rootIdentities() (map[string]string, error) {
	if err := p.checkRoots(); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for class, info := range p.pins {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, recovery.ErrUnsafe
		}
		out[class] = fmt.Sprintf("%d:%d", uint64(st.Dev), st.Ino)
	}
	return out, nil
}

func (p *treeRetainedInstall) validManagedPath(name string) bool {
	class, relative, ok := strings.Cut(name, "/")
	return ok && fs.ValidPath(name) && !strings.ContainsAny(name, "\\\r\n\x00") && p.roots[class] != "" &&
		(class != "data" || !treeRetainedProtected(relative) && recovery.SelectedPath(p.selectData, relative, false))
}

// retain publishes a private, complete snapshot without replacing an existing
// one. An unfinished scratch directory is retained for explicit inspection.
func (p *treeRetainedInstall) retain(ctx context.Context, failed string) error {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(failed) || filepath.Clean(failed) != failed {
		return recovery.ErrUnsafe
	}
	parent := filepath.Dir(failed)
	info, err := os.Lstat(parent)
	st, ok := func() (*syscall.Stat_t, bool) {
		if info == nil {
			return nil, false
		}
		v, ok := info.Sys().(*syscall.Stat_t)
		return v, ok
	}()
	if err != nil || !ok || !info.IsDir() || info.Mode().Perm() != 0700 || st.Uid != uint32(os.Geteuid()) {
		return recovery.ErrUnsafe
	}
	canonical, err := filepath.EvalSymlinks(parent)
	if err != nil || canonical != parent {
		return recovery.ErrUnsafe
	}
	for _, root := range p.roots {
		if treePathsOverlap(failed, root) {
			return recovery.ErrUnsafe
		}
	}
	if _, err := os.Lstat(failed); err == nil {
		if _, err = p.verifyRetained(ctx, failed); err != nil {
			return err
		}
		p.retained = failed
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	identities, err := p.rootIdentities()
	if err != nil {
		return err
	}
	current, err := inventoryState(ctx, p.roots, p.selectData)
	if err != nil {
		return err
	}
	var need uint64 = 512 << 20
	for _, file := range current {
		if !p.validManagedPath(file.Path) || file.Bytes < 0 || uint64(file.Bytes) > ^uint64(0)-need {
			return recovery.ErrUnsafe
		}
		need += uint64(file.Bytes)
	}
	free, err := diskFree(parent)
	if err != nil || free < need {
		return errors.New("insufficient private space for retained failed state")
	}
	stage, err := os.MkdirTemp(parent, ".fc-tree-retained-")
	if err != nil {
		return err
	}
	stageRoot, err := os.OpenRoot(stage)
	if err != nil {
		return err
	}
	defer stageRoot.Close()
	snapshot := treeRetainedSnapshot{Version: 1, Archive: p.report.SHA256, Roots: identities, Files: []recovery.Entry{}}
	for _, item := range current {
		if err = ctx.Err(); err != nil {
			return err
		}
		class, relative, _ := strings.Cut(item.Path, "/")
		source, e := p.openPinnedRoot(class)
		if e != nil {
			return e
		}
		actual, e := treeRetainedHash(ctx, source, relative)
		if e != nil {
			source.Close()
			return e
		}
		actual.Path = item.Path
		destination := filepath.Join(stage, class)
		if e = os.MkdirAll(filepath.Join(destination, filepath.FromSlash(path.Dir(relative))), 0700); e != nil {
			source.Close()
			return e
		}
		copyEntry := actual
		copyEntry.Mode, copyEntry.UID, copyEntry.GID = 0600, os.Geteuid(), os.Getegid()
		stageClass, e := os.OpenRoot(destination)
		if e != nil {
			source.Close()
			return e
		}
		e = treeRetainedReplace(ctx, source, stageClass, relative, copyEntry, nil)
		stageClass.Close()
		if e != nil {
			source.Close()
			return e
		}
		// Detect a changed source even if bytes happened to be copied before it changed.
		after, e := treeRetainedHash(ctx, source, relative)
		source.Close()
		after.Path = item.Path
		if e != nil || after != actual {
			return recovery.ErrUnsafe
		}
		snapshot.Files = append(snapshot.Files, actual)
	}
	if err = p.checkRoots(); err != nil {
		return err
	}
	if err = exclusiveJSON(filepath.Join(stage, treeRetainedSnapshotName), snapshot); err != nil {
		return err
	}
	if err = fs.WalkDir(stageRoot.FS(), ".", func(name string, item fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if item.IsDir() {
			return fsutil.SyncDirectory(stageRoot, name)
		}
		return nil
	}); err != nil {
		return err
	}
	parentRoot, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer parentRoot.Close()
	opened, err := parentRoot.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return recovery.ErrUnsafe
	}
	parentFD, err := parentRoot.Open(".")
	if err != nil {
		return err
	}
	defer parentFD.Close()
	if err = unix.Renameat2(int(parentFD.Fd()), filepath.Base(stage), int(parentFD.Fd()), filepath.Base(failed), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err = fsutil.SyncDirectory(parentRoot, "."); err != nil {
		return err
	}
	if _, err = p.verifyRetained(ctx, failed); err != nil {
		return err
	}
	p.retained = failed
	return nil
}

func prefixTreeStatePaths() []string {
	var out []string
	for _, p := range sealedtree.MasterStatePaths() {
		out = append(out, "data/"+p)
	}
	return out
}

func (p *treeRetainedInstall) checkRoots() error {
	for class, dir := range p.roots {
		info, err := os.Lstat(dir)
		if err != nil || !sameTreeRuntimeDirectory(p.pins[class], info) {
			return recovery.ErrUnsafe
		}
	}
	return nil
}

func (p *treeRetainedInstall) openPinnedRoot(class string) (*os.Root, error) {
	root, err := os.OpenRoot(p.roots[class])
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !sameTreeRuntimeDirectory(p.pins[class], opened) {
		root.Close()
		return nil, recovery.ErrUnsafe
	}
	return root, nil
}

// All destination mutations use the verified mount descriptor and a pinned
// parent descriptor, never a second lookup of the host mount path.
func treeRetainedReplace(ctx context.Context, source *os.Root, destination *os.Root, relative string, entry recovery.Entry, previous *recovery.Entry) error {
	parentName, base := path.Dir(relative), path.Base(relative)
	before, err := destination.Lstat(parentName)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return recovery.ErrUnsafe
	}
	parent, err := destination.OpenRoot(parentName)
	if err != nil {
		return err
	}
	defer parent.Close()
	opened, err := parent.Stat(".")
	if err != nil || !sameTreeRuntimeDirectory(before, opened) {
		return recovery.ErrUnsafe
	}
	in, err := source.Open(relative)
	if err != nil {
		return err
	}
	defer in.Close()
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := ".foc-tree-state-" + hex.EncodeToString(nonce[:])
	f, err := parent.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer parent.Remove(temporary)
	h := sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(f, h), &stateReader{ctx, in}, make([]byte, 64<<10))
	if err == nil && (n != entry.Bytes || hex.EncodeToString(h.Sum(nil)) != entry.SHA256) {
		err = recovery.ErrUnsafe
	}
	if err == nil {
		err = f.Chown(entry.UID, entry.GID)
	}
	if err == nil {
		err = f.Chmod(os.FileMode(entry.Mode))
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	current, err := destination.Lstat(parentName)
	if err != nil || !sameTreeRuntimeDirectory(before, current) || ctx.Err() != nil {
		return recovery.ErrUnsafe
	}
	if previous == nil {
		if _, e := parent.Lstat(base); !os.IsNotExist(e) {
			return recovery.ErrUnsafe
		}
	} else {
		same, exists, e := treeRetainedSameFile(ctx, parent, base, *previous)
		if e != nil || !exists || !same {
			return recovery.ErrUnsafe
		}
	}
	if err = parent.Rename(temporary, base); err != nil {
		return err
	}
	if err = fsutil.SyncDirectory(parent, "."); err != nil {
		return err
	}
	current, err = destination.Lstat(parentName)
	if err != nil || !sameTreeRuntimeDirectory(before, current) {
		return recovery.ErrUnsafe
	}
	return nil
}

func treeRetainedRemove(ctx context.Context, destination *os.Root, relative string, expected *recovery.Entry) error {
	info, err := destination.Lstat(relative)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return recovery.ErrUnsafe
	}
	parentName, base := path.Dir(relative), path.Base(relative)
	before, err := destination.Lstat(parentName)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return recovery.ErrUnsafe
	}
	parent, err := destination.OpenRoot(parentName)
	if err != nil {
		return err
	}
	defer parent.Close()
	opened, err := parent.Stat(".")
	if err != nil || !sameTreeRuntimeDirectory(before, opened) {
		return recovery.ErrUnsafe
	}
	current, err := parent.Lstat(base)
	if err != nil || !os.SameFile(info, current) {
		return recovery.ErrUnsafe
	}
	if expected != nil {
		same, _, e := treeRetainedSameFile(ctx, parent, base, *expected)
		if e != nil || !same {
			return recovery.ErrUnsafe
		}
	}
	current, err = destination.Lstat(parentName)
	if err != nil || !sameTreeRuntimeDirectory(before, current) || ctx.Err() != nil {
		return recovery.ErrUnsafe
	}
	if err = parent.Remove(base); err != nil {
		return err
	}
	if err = fsutil.SyncDirectory(parent, "."); err != nil {
		return err
	}
	current, err = destination.Lstat(parentName)
	if err != nil || !sameTreeRuntimeDirectory(before, current) {
		return recovery.ErrUnsafe
	}
	return nil
}

// treeRetainedHash pins and rechecks the inode including ctime while hashing.
func treeRetainedHash(ctx context.Context, root *os.Root, name string) (recovery.Entry, error) {
	var out recovery.Entry
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return out, recovery.ErrUnsafe
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return out, recovery.ErrUnsafe
	}
	f, err := root.Open(name)
	if err != nil {
		return out, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameTreeRuntimeFile(info, opened) {
		return out, recovery.ErrUnsafe
	}
	h := sha256.New()
	n, err := io.CopyBuffer(h, &stateReader{ctx, f}, make([]byte, 64<<10))
	after, aerr := f.Stat()
	current, cerr := root.Lstat(name)
	if err != nil || aerr != nil || cerr != nil || n != info.Size() || !sameTreeRuntimeFile(info, after) || !sameTreeRuntimeFile(info, current) {
		return out, recovery.ErrUnsafe
	}
	return recovery.Entry{Path: name, Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil)), Mode: int64(info.Mode().Perm()), UID: int(st.Uid), GID: int(st.Gid)}, nil
}

func (p *treeRetainedInstall) verifyRetained(ctx context.Context, directory string) (treeRetainedSnapshot, error) {
	var snapshot treeRetainedSnapshot
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return snapshot, recovery.ErrUnsafe
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return snapshot, recovery.ErrUnsafe
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return snapshot, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return snapshot, recovery.ErrUnsafe
	}
	marker, err := treeRetainedHash(ctx, root, treeRetainedSnapshotName)
	if err != nil || marker.Mode != 0600 || marker.UID != os.Geteuid() || marker.Bytes > 32<<20 {
		return snapshot, recovery.ErrUnsafe
	}
	markerFile, err := root.Open(treeRetainedSnapshotName)
	if err != nil {
		return snapshot, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(markerFile, marker.Bytes+1))
	closeErr := markerFile.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) != marker.Bytes {
		return snapshot, recovery.ErrUnsafe
	}
	markerAfter, err := treeRetainedHash(ctx, root, treeRetainedSnapshotName)
	sum := sha256.Sum256(raw)
	if err != nil || markerAfter != marker || hex.EncodeToString(sum[:]) != marker.SHA256 {
		return snapshot, recovery.ErrUnsafe
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&snapshot) != nil || dec.Decode(new(any)) != io.EOF || snapshot.Version != 1 || snapshot.Archive != p.report.SHA256 {
		return snapshot, recovery.ErrUnsafe
	}
	identities, err := p.rootIdentities()
	if err != nil || !maps.Equal(snapshot.Roots, identities) {
		return snapshot, recovery.ErrUnsafe
	}
	allowed := map[string]bool{".": true, treeRetainedSnapshotName: true}
	previous := ""
	for _, entry := range snapshot.Files {
		if !p.validManagedPath(entry.Path) || entry.Path <= previous || entry.Bytes < 0 || len(entry.SHA256) != 64 {
			return snapshot, recovery.ErrUnsafe
		}
		previous = entry.Path
		allowed[entry.Path] = true
		for parent := path.Dir(entry.Path); parent != "."; parent = path.Dir(parent) {
			allowed[parent] = true
		}
		actual, e := treeRetainedHash(ctx, root, entry.Path)
		if e != nil || actual.Bytes != entry.Bytes || actual.SHA256 != entry.SHA256 || actual.Mode != 0600 || actual.UID != os.Geteuid() {
			return snapshot, recovery.ErrUnsafe
		}
	}
	if err = fs.WalkDir(root.FS(), ".", func(name string, item fs.DirEntry, e error) error {
		if e != nil || ctx.Err() != nil || !allowed[name] || item.Type()&os.ModeSymlink != 0 || !item.IsDir() && !item.Type().IsRegular() {
			return recovery.ErrUnsafe
		}
		if item.IsDir() {
			info, err := item.Info()
			if err != nil {
				return recovery.ErrUnsafe
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0700 {
				return recovery.ErrUnsafe
			}
		}
		return nil
	}); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func (p *treeRetainedInstall) verifyMaterial(ctx context.Context, material string) error {
	if ctx == nil || ctx.Err() != nil || p.retained == "" || !filepath.IsAbs(material) || filepath.Clean(material) != material {
		return recovery.ErrUnsafe
	}
	for _, root := range p.roots {
		if treePathsOverlap(material, root) {
			return recovery.ErrUnsafe
		}
	}
	if treePathsOverlap(material, p.retained) {
		return recovery.ErrUnsafe
	}
	if _, err := p.verifyRetained(ctx, p.retained); err != nil {
		return err
	}
	return recovery.CheckTreeMaterial(ctx, material, p.report)
}

func treeRetainedSameFile(ctx context.Context, root *os.Root, name string, expected recovery.Entry) (bool, bool, error) {
	if _, err := root.Lstat(name); os.IsNotExist(err) {
		return false, false, nil
	} else if err != nil {
		return false, false, err
	}
	actual, err := treeRetainedHash(ctx, root, name)
	if err != nil {
		return false, true, err
	}
	return actual.Bytes == expected.Bytes && actual.SHA256 == expected.SHA256 && actual.Mode == expected.Mode && actual.UID == expected.UID && actual.GID == expected.GID, true, nil
}

func (p *treeRetainedInstall) ensureDirectories(ctx context.Context) error {
	for _, dir := range p.dirs {
		if err := ctx.Err(); err != nil {
			return err
		}
		class, relative, nested := strings.Cut(dir.Path, "/")
		if !nested {
			relative = "."
		}
		root, err := p.openPinnedRoot(class)
		if err != nil {
			return err
		}
		info, err := root.Lstat(relative)
		if os.IsNotExist(err) && nested {
			// Parents are explicitly present in the validated archive; never
			// synthesize a missing, unaudited path component.
			parentName, base := path.Dir(relative), path.Base(relative)
			before, e := root.Lstat(parentName)
			if e != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
				root.Close()
				return recovery.ErrUnsafe
			}
			parent, e := root.OpenRoot(parentName)
			if e != nil {
				root.Close()
				return e
			}
			opened, e := parent.Stat(".")
			if e != nil || !sameTreeRuntimeDirectory(before, opened) {
				parent.Close()
				root.Close()
				return recovery.ErrUnsafe
			}
			err = parent.Mkdir(base, 0700)
			if err == nil {
				err = parent.Chown(base, dir.UID, dir.GID)
			}
			if err == nil {
				err = parent.Chmod(base, os.FileMode(dir.Mode))
			}
			if err == nil {
				err = fsutil.SyncDirectory(parent, base)
			}
			if err == nil {
				err = fsutil.SyncDirectory(parent, ".")
			}
			current, e := root.Lstat(parentName)
			if e != nil || !sameTreeRuntimeDirectory(before, current) {
				err = recovery.ErrUnsafe
			}
			parent.Close()
			if err == nil {
				info, err = root.Lstat(relative)
			}
		}
		if err == nil {
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || int64(info.Mode().Perm()) != dir.Mode || int(st.Uid) != dir.UID || int(st.Gid) != dir.GID {
				err = recovery.ErrUnsafe
			}
		}
		root.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// Unknown directories are never silently deleted or adopted as restored
// state. DATA_ROOT subtrees outside the selection are pruned without reads.
func (p *treeRetainedInstall) validateExistingDirectories(ctx context.Context) error {
	wanted := map[string]bool{}
	for _, dir := range p.dirs {
		wanted[dir.Path] = true
	}
	for class := range p.roots {
		root, err := p.openPinnedRoot(class)
		if err != nil {
			return err
		}
		err = fs.WalkDir(root.FS(), ".", func(name string, item fs.DirEntry, e error) error {
			if e != nil || ctx.Err() != nil {
				return recovery.ErrUnsafe
			}
			if class == "data" && !recovery.SelectedPath(p.selectData, name, item.IsDir()) {
				if item.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if item.Type()&os.ModeSymlink != 0 || !item.IsDir() && !item.Type().IsRegular() {
				return recovery.ErrUnsafe
			}
			if item.IsDir() && name != "." && !wanted[class+"/"+name] {
				return recovery.ErrUnsafe
			}
			return nil
		})
		root.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *treeRetainedInstall) install(ctx context.Context, material string) error {
	if err := p.verifyMaterial(ctx, material); err != nil {
		return err
	}
	snapshot, err := p.verifyRetained(ctx, p.retained)
	if err != nil {
		return err
	}
	if err = p.checkRoots(); err != nil {
		return err
	}
	if err = checkRestoreDestinationCapacity(p.roots, p.entries, diskFree); err != nil {
		return err
	}
	if err = p.validateExistingDirectories(ctx); err != nil {
		return err
	}
	if err = p.ensureDirectories(ctx); err != nil {
		return err
	}
	previous := map[string]recovery.Entry{}
	for _, entry := range snapshot.Files {
		previous[entry.Path] = entry
	}
	wanted := map[string]recovery.Entry{}
	for _, entry := range p.entries {
		wanted[entry.Path] = entry
	}
	current, err := inventoryState(ctx, p.roots, p.selectData)
	if err != nil {
		return err
	}
	for _, entry := range current {
		if !p.validManagedPath(entry.Path) {
			return recovery.ErrUnsafe
		}
		if _, ok := wanted[entry.Path]; ok {
			continue
		}
		prior, ok := previous[entry.Path]
		if !ok {
			return errors.New("unexpected retained state appeared after snapshot")
		}
		class, relative, _ := strings.Cut(entry.Path, "/")
		root, e := p.openPinnedRoot(class)
		if e != nil {
			return e
		}
		e = treeRetainedRemove(ctx, root, relative, &prior)
		root.Close()
		if e != nil {
			return e
		}
	}
	for _, entry := range p.entries {
		if err = ctx.Err(); err != nil {
			return err
		}
		class, relative, _ := strings.Cut(entry.Path, "/")
		root, e := p.openPinnedRoot(class)
		if e != nil {
			return e
		}
		same, exists, e := treeRetainedSameFile(ctx, root, relative, entry)
		if e == nil && !same {
			if prior, wasPresent := previous[entry.Path]; wasPresent {
				if !exists {
					e = recovery.ErrUnsafe
				} else if samePrior, _, x := treeRetainedSameFile(ctx, root, relative, prior); x != nil || !samePrior {
					e = recovery.ErrUnsafe
				}
			} else if exists {
				e = recovery.ErrUnsafe
			}
		}
		if e == nil && !same {
			var source *os.Root
			source, e = os.OpenRoot(filepath.Join(material, class))
			if e == nil {
				var prior *recovery.Entry
				if original, ok := previous[entry.Path]; ok {
					prior = &original
				}
				e = treeRetainedReplace(ctx, source, root, relative, entry, prior)
				source.Close()
			}
		}
		root.Close()
		if e != nil {
			return e
		}
	}
	return p.verifyInstalled(ctx, false)
}

func (p *treeRetainedInstall) isSQLitePath(name string) bool {
	return name == "data/"+p.database || name == "data/"+p.database+"-wal" || name == "data/"+p.database+"-shm"
}

func (p *treeRetainedInstall) verifyInstalled(ctx context.Context, exceptSQLite bool) error {
	if err := p.checkRoots(); err != nil {
		return err
	}
	if err := p.validateExistingDirectories(ctx); err != nil {
		return err
	}
	wanted := map[string]recovery.Entry{}
	for _, entry := range p.entries {
		wanted[entry.Path] = entry
	}
	current, err := inventoryState(ctx, p.roots, p.selectData)
	if err != nil {
		return err
	}
	for _, entry := range current {
		if !p.validManagedPath(entry.Path) {
			return recovery.ErrUnsafe
		}
		if exceptSQLite && p.isSQLitePath(entry.Path) {
			continue
		}
		if _, ok := wanted[entry.Path]; !ok {
			return recovery.ErrUnsafe
		}
	}
	for _, entry := range p.entries {
		if exceptSQLite && p.isSQLitePath(entry.Path) {
			continue
		}
		class, relative, _ := strings.Cut(entry.Path, "/")
		root, e := p.openPinnedRoot(class)
		if e != nil {
			return e
		}
		same, _, e := treeRetainedSameFile(ctx, root, relative, entry)
		root.Close()
		if e != nil || !same {
			return recovery.ErrUnsafe
		}
	}
	return nil
}

// repairSQLite is permitted only before rebind intent publication. The caller
// enforces that journal/intent boundary under the same held native leases.
func (p *treeRetainedInstall) repairSQLite(ctx context.Context, material string) error {
	if err := p.verifyMaterial(ctx, material); err != nil {
		return err
	}
	if err := p.verifyInstalled(ctx, true); err != nil {
		return err
	}
	if err := checkRestoreDestinationCapacity(p.roots, p.entries, diskFree); err != nil {
		return err
	}
	byPath := map[string]recovery.Entry{}
	for _, entry := range p.entries {
		if p.isSQLitePath(entry.Path) {
			byPath[entry.Path] = entry
		}
	}
	for _, relative := range []string{p.database, p.database + "-wal", p.database + "-shm"} {
		entry, present := byPath["data/"+relative]
		root, err := p.openPinnedRoot("data")
		if err != nil {
			return err
		}
		if !present {
			e := treeRetainedRemove(ctx, root, relative, nil)
			root.Close()
			if e != nil {
				return e
			}
			continue
		}
		same, exists, err := treeRetainedSameFile(ctx, root, relative, entry)
		if err == nil && !same {
			var previous *recovery.Entry
			if exists {
				var observed recovery.Entry
				observed, err = treeRetainedHash(ctx, root, relative)
				previous = &observed
			}
			var source *os.Root
			if err == nil {
				source, err = os.OpenRoot(filepath.Join(material, "data"))
			}
			if err == nil {
				err = treeRetainedReplace(ctx, source, root, relative, entry, previous)
				source.Close()
			}
		}
		root.Close()
		if err != nil {
			return err
		}
	}
	return p.verifyInstalled(ctx, false)
}
