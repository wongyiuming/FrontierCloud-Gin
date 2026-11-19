//go:build linux

package recovery

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type treeStageContextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (w treeStageContextWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.writer.Write(p)
}

// WriteCommittedTreeBackupClasses streams only receipt-selected non-native
// roots after the child has acknowledged its maintenance/SQLite lease. The
// caller must validate the receipt, stop external writers and maintain the IPC
// session throughout. No final nonce/digest is emitted if any source changes.
func WriteCommittedTreeBackupClasses(ctx context.Context, output io.Writer, sources []Root, maxBytes uint64, nonce string, check func() error) error {
	return WriteCommittedTreeBackupClassesFinal(ctx, output, sources, maxBytes, nonce, check, check)
}

// WriteCommittedTreeBackupClassesFinal allows cheap per-entry checks and a
// stronger authority recheck immediately before writing the commit frame.
func WriteCommittedTreeBackupClassesFinal(ctx context.Context, output io.Writer, sources []Root, maxBytes uint64, nonce string, check, finalCheck func() error) error {
	if ctx == nil || output == nil || check == nil || finalCheck == nil || maxBytes == 0 || maxBytes > 10*1024*1024*1024*1024 || len(sources) == 0 || len(sources) > 4 || len(nonce) != 64 {
		return ErrUnsafe
	}
	nonceRaw, e := hex.DecodeString(nonce)
	if e != nil || len(nonceRaw) != 32 || hex.EncodeToString(nonceRaw) != nonce || check() != nil {
		return ErrUnsafe
	}
	digest := sha256.New()
	tw := tar.NewWriter(treeStageContextWriter{ctx, io.MultiWriter(output, digest)})
	roots := map[string]*os.Root{}
	rootPaths := map[string]string{}
	pins := map[string]os.FileInfo{}
	directories := map[string]os.FileInfo{}
	var total, metadataBytes uint64
	count := 0
	defer func() {
		for _, root := range roots {
			root.Close()
		}
	}()
	ordered := append([]Root(nil), sources...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Class < ordered[j].Class })
	for _, source := range ordered {
		switch source.Class {
		case "deployment", "redis_data", "certificate_state", "certificate_published":
		default:
			return ErrUnsafe
		}
		if roots[source.Class] != nil || source.IncludePaths != nil || source.staged != nil {
			return ErrUnsafe
		}
		info, err := os.Lstat(source.Directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafe
		}
		absolute, err := filepath.Abs(source.Directory)
		if err != nil {
			return ErrUnsafe
		}
		for _, old := range rootPaths {
			a, e := filepath.Rel(old, absolute)
			if e != nil || a == "." || a != ".." && !strings.HasPrefix(a, ".."+string(filepath.Separator)) {
				return ErrUnsafe
			}
			b, e := filepath.Rel(absolute, old)
			if e != nil || b == "." || b != ".." && !strings.HasPrefix(b, ".."+string(filepath.Separator)) {
				return ErrUnsafe
			}
		}
		root, err := os.OpenRoot(absolute)
		if err != nil {
			return err
		}
		roots[source.Class] = root
		rootPaths[source.Class] = absolute
		opened, err := root.Stat(".")
		if err != nil || !sameArchiveSource(info, opened) {
			return ErrUnsafe
		}
		err = fs.WalkDir(root.FS(), ".", func(name string, item fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if check() != nil {
				return ErrUnsafe
			}
			count++
			if count > MaxFiles {
				return ErrUnsafe
			}
			if item.Type()&os.ModeSymlink != 0 {
				return ErrUnsafe
			}
			key := source.Class
			if name != "." {
				key += "/" + name
			}
			if len(key) > 4096 || strings.ContainsAny(key, "\\\\\x00\r\n") {
				return ErrUnsafe
			}
			before, err := root.Lstat(name)
			if err != nil {
				return err
			}
			h, err := tar.FileInfoHeader(before, "")
			if err != nil {
				return err
			}
			h.Name = key
			if before.IsDir() {
				directories[key] = before
				raw, e := json.Marshal(Directory{Path: key, Mode: h.Mode & 0777, UID: h.Uid, GID: h.Gid})
				if e != nil || uint64(len(raw)+1) > uint64(MaxManifest)-metadataBytes {
					return ErrUnsafe
				}
				metadataBytes += uint64(len(raw) + 1)
				return tw.WriteHeader(h)
			}
			if !before.Mode().IsRegular() || before.Size() < 0 || uint64(before.Size()) > maxBytes-total {
				return ErrUnsafe
			}
			total += uint64(before.Size())
			entry, err := hashFile(ctx, root, name)
			if err != nil {
				return err
			}
			after, err := root.Lstat(name)
			if err != nil || !sameArchiveSource(before, after) {
				return ErrUnsafe
			}
			pins[key] = before
			raw, err := json.Marshal(Entry{Path: key, Bytes: entry.Bytes, SHA256: entry.SHA256, Mode: entry.Mode, UID: entry.UID, GID: entry.GID})
			if err != nil || uint64(len(raw)+1) > uint64(MaxManifest)-metadataBytes {
				return ErrUnsafe
			}
			metadataBytes += uint64(len(raw) + 1)
			if err = tw.WriteHeader(h); err != nil {
				return err
			}
			f, err := root.Open(name)
			if err != nil {
				return err
			}
			opened, err := f.Stat()
			if err != nil || !sameArchiveSource(before, opened) {
				f.Close()
				return ErrUnsafe
			}
			fileHash := sha256.New()
			n, copyErr := io.CopyBuffer(io.MultiWriter(tw, fileHash), contextReader{ctx, io.LimitReader(f, before.Size()+1)}, make([]byte, 64<<10))
			final, statErr := f.Stat()
			closeErr := f.Close()
			if copyErr != nil || statErr != nil || closeErr != nil || n != before.Size() || !sameArchiveSource(before, final) || hex.EncodeToString(fileHash.Sum(nil)) != entry.SHA256 {
				return ErrUnsafe
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if roots["deployment"] == nil {
		return ErrUnsafe
	}
	seenFiles, seenDirs := map[string]bool{}, map[string]bool{}
	for _, source := range ordered {
		root := roots[source.Class]
		err := fs.WalkDir(root.FS(), ".", func(name string, item fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if check() != nil {
				return ErrUnsafe
			}
			if item.Type()&os.ModeSymlink != 0 {
				return ErrUnsafe
			}
			key := source.Class
			if name != "." {
				key += "/" + name
			}
			info, e := item.Info()
			if e != nil {
				return e
			}
			if info.IsDir() {
				if !sameArchiveSource(directories[key], info) {
					return ErrUnsafe
				}
				seenDirs[key] = true
				return nil
			}
			if !info.Mode().IsRegular() || !sameArchiveSource(pins[key], info) {
				return ErrUnsafe
			}
			seenFiles[key] = true
			return nil
		})
		if err != nil {
			return err
		}
		actual, e := os.Lstat(rootPaths[source.Class])
		if e != nil || !sameArchiveSource(directories[source.Class], actual) {
			return ErrUnsafe
		}
	}
	if len(seenFiles) != len(pins) || len(seenDirs) != len(directories) || check() != nil || ctx.Err() != nil {
		return ErrUnsafe
	}
	if e = tw.Close(); e != nil {
		return e
	}
	if finalCheck() != nil || ctx.Err() != nil {
		return ErrUnsafe
	}
	var frame [64]byte
	copy(frame[:32], digest.Sum(nil))
	copy(frame[32:], nonceRaw)
	n, e := output.Write(frame[:])
	if e != nil {
		return e
	}
	if n != len(frame) {
		return io.ErrShortWrite
	}
	return nil
}
