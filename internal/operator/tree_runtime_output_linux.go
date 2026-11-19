//go:build linux

package operator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

// publishTreeRuntimeArchive is the output half of the unregistered tree backup
// workflow. The future caller MUST first validate the deployment receipt and
// bind tmpVolume to the web service's actual mount. This function does not
// start a container, establish the maintenance lease, or authorize restore.
// sourceDir and sourceName are single names within that verified volume.
func publishTreeRuntimeArchive(ctx context.Context, dataRoot, tmpVolume, sourceDir, sourceName, output, expectedSHA, nodeID string, maxBytes, safetyBytes uint64) (out recovery.Report, err error) {
	if ctx == nil || len(expectedSHA) != 64 || len(nodeID) != 32 || maxBytes == 0 || !filepath.IsAbs(dataRoot) || !filepath.IsAbs(tmpVolume) || !filepath.IsAbs(output) || filepath.Base(sourceDir) != sourceDir || sourceDir == "." || sourceDir == ".." || filepath.Base(sourceName) != sourceName || sourceName == "." || sourceName == ".." || strings.ContainsAny(sourceDir+sourceName, "/\\\\\x00") {
		return out, recovery.ErrUnsafe
	}
	decodedSHA, shaErr := hex.DecodeString(expectedSHA)
	decodedNode, nodeErr := hex.DecodeString(nodeID)
	if shaErr != nil || nodeErr != nil || len(decodedSHA) != 32 || len(decodedNode) != 16 || hex.EncodeToString(decodedSHA) != expectedSHA || hex.EncodeToString(decodedNode) != nodeID {
		return out, recovery.ErrUnsafe
	}
	dataInfo, e := os.Lstat(dataRoot)
	if e != nil || !dataInfo.IsDir() || dataInfo.Mode()&os.ModeSymlink != 0 {
		return out, recovery.ErrUnsafe
	}
	dataStat, ok := dataInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return out, recovery.ErrUnsafe
	}
	tmpInfo, e := os.Lstat(tmpVolume)
	if e != nil || !tmpInfo.IsDir() || tmpInfo.Mode()&os.ModeSymlink != 0 {
		return out, recovery.ErrUnsafe
	}
	tmpRoot, e := os.OpenRoot(tmpVolume)
	if e != nil {
		return out, e
	}
	defer tmpRoot.Close()
	openedTmp, e := tmpRoot.Stat(".")
	if e != nil || !os.SameFile(tmpInfo, openedTmp) {
		return out, recovery.ErrUnsafe
	}
	stageInfo, e := tmpRoot.Lstat(sourceDir)
	if e != nil || !stageInfo.IsDir() || stageInfo.Mode().Perm() != 0700 {
		return out, recovery.ErrUnsafe
	}
	stageStat, ok := stageInfo.Sys().(*syscall.Stat_t)
	if !ok || stageStat.Uid != dataStat.Uid {
		return out, recovery.ErrUnsafe
	}
	stage, e := tmpRoot.OpenRoot(sourceDir)
	if e != nil {
		return out, e
	}
	defer stage.Close()
	openedStage, e := stage.Stat(".")
	if e != nil || !os.SameFile(stageInfo, openedStage) {
		return out, recovery.ErrUnsafe
	}
	before, e := stage.Lstat(sourceName)
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() <= 0 || uint64(before.Size()) > maxBytes {
		return out, recovery.ErrUnsafe
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || beforeStat.Uid != dataStat.Uid || beforeStat.Nlink != 1 {
		return out, recovery.ErrUnsafe
	}
	source, e := stage.Open(sourceName)
	if e != nil {
		return out, e
	}
	defer source.Close()
	opened, e := source.Stat()
	if e != nil || !sameTreeRuntimeFile(before, opened) {
		return out, recovery.ErrUnsafe
	}
	parentPath := filepath.Dir(output)
	outputName := filepath.Base(output)
	if outputName == "." || outputName == ".." {
		return out, recovery.ErrUnsafe
	}
	parentInfo, e := os.Lstat(parentPath)
	if e != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0700 || parentInfo.Mode()&os.ModeSymlink != 0 {
		return out, recovery.ErrUnsafe
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != uint32(os.Geteuid()) {
		return out, recovery.ErrUnsafe
	}
	for _, root := range []string{dataRoot, tmpVolume} {
		rel, e := filepath.Rel(root, output)
		if e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return out, recovery.ErrUnsafe
		}
	}
	parent, e := os.OpenRoot(parentPath)
	if e != nil {
		return out, e
	}
	defer parent.Close()
	openedParent, e := parent.Stat(".")
	if e != nil || !os.SameFile(parentInfo, openedParent) {
		return out, recovery.ErrUnsafe
	}
	if _, e = parent.Lstat(outputName); !errors.Is(e, os.ErrNotExist) {
		return out, recovery.ErrUnsafe
	}
	free, e := diskFree(parentPath)
	if e != nil || uint64(before.Size()) > free || safetyBytes > free-uint64(before.Size()) {
		return out, errors.New("insufficient private archive output capacity")
	}
	var token [16]byte
	if _, e = rand.Read(token[:]); e != nil {
		return out, e
	}
	tempName := ".fc-tree-backup-" + hex.EncodeToString(token[:])
	f, e := parent.OpenFile(tempName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return out, e
	}
	tempInfo, e := f.Stat()
	if e != nil {
		f.Close()
		return out, e
	}
	defer func() {
		f.Close()
		current, x := parent.Lstat(tempName)
		if x == nil && os.SameFile(tempInfo, current) {
			_ = parent.Remove(tempName)
			_ = fsutil.SyncDirectory(parent, ".")
		}
	}()
	h := sha256.New()
	n, e := io.CopyBuffer(io.MultiWriter(f, h), treeRuntimeReader{ctx, io.LimitReader(source, before.Size()+1)}, make([]byte, 64<<10))
	if e != nil || n != before.Size() || hex.EncodeToString(h.Sum(nil)) != expectedSHA {
		return out, recovery.ErrUnsafe
	}
	after, e := source.Stat()
	current, x := stage.Lstat(sourceName)
	rootNow, y := tmpRoot.Lstat(sourceDir)
	tmpNow, tmpErr := os.Lstat(tmpVolume)
	parentNow, parentErr := os.Lstat(parentPath)
	dataNow, z := os.Lstat(dataRoot)
	if e != nil || x != nil || y != nil || z != nil || tmpErr != nil || parentErr != nil || !sameTreeRuntimeFile(before, after) || !sameTreeRuntimeFile(before, current) || !sameTreeRuntimeDirectory(stageInfo, rootNow) || !sameTreeRuntimeDirectory(tmpInfo, tmpNow) || !sameTreeRuntimeDirectory(parentInfo, parentNow) || !sameTreeRuntimeDirectory(dataInfo, dataNow) {
		return out, recovery.ErrUnsafe
	}
	if e = f.Sync(); e != nil {
		return out, e
	}
	if e = f.Close(); e != nil {
		return out, e
	}
	report, e := recovery.CheckTreeArchiveAuthenticated(ctx, filepath.Join(parentPath, tempName), expectedSHA)
	if e != nil || report.Manifest.NodeID != nodeID {
		return out, recovery.ErrUnsafe
	}
	// Recheck every path after authentication and immediately before Link.
	parentNow, parentErr = os.Lstat(parentPath)
	tmpNow, tmpErr = os.Lstat(tmpVolume)
	rootNow, y = tmpRoot.Lstat(sourceDir)
	dataNow, z = os.Lstat(dataRoot)
	if parentErr != nil || tmpErr != nil || y != nil || z != nil || !sameTreeRuntimeDirectory(parentInfo, parentNow) || !sameTreeRuntimeDirectory(tmpInfo, tmpNow) || !sameTreeRuntimeDirectory(stageInfo, rootNow) || !sameTreeRuntimeDirectory(dataInfo, dataNow) {
		return out, recovery.ErrUnsafe
	}
	current, e = parent.Lstat(tempName)
	if e != nil || !os.SameFile(tempInfo, current) {
		return out, recovery.ErrUnsafe
	}
	if e = parent.Link(tempName, outputName); e != nil {
		return out, e
	}
	if e = fsutil.SyncDirectory(parent, "."); e != nil {
		return out, e
	}
	return report, nil
}

type treeRuntimeReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r treeRuntimeReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
func sameTreeRuntimeFile(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Size() != b.Size() || a.Mode() != b.Mode() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Ctim == y.Ctim
}

func sameTreeRuntimeDirectory(a, b os.FileInfo) bool {
	if a == nil || b == nil || !a.IsDir() || !b.IsDir() || !os.SameFile(a, b) || a.Mode() != b.Mode() {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Uid == y.Uid && x.Gid == y.Gid
}
