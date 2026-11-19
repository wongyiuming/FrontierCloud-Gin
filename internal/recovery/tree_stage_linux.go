//go:build linux

package recovery

import (
	"archive/tar"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
)

// ReceiveTreeBackupClasses consumes only receipt-selected non-native state
// classes in a private runtime-owned scratch root. Source UID/GID/mode from the
// trusted foc stream are carried in unexported metadata; local staged copies
// remain owned by the runtime user. Call only inside the native lease callback.
// The caller must bound/cancel the underlying stream and clean its own staging
// on failure; this function never removes an input or changes source ownership.
func ReceiveTreeBackupClasses(ctx context.Context, input io.Reader, stage *os.Root, classes []string, maxBytes uint64) ([]Root, error) {
	return receiveTreeBackupClasses(ctx, input, stage, classes, maxBytes, "")
}

// ReceiveCommittedTreeBackupClasses requires the parent's final digest/nonce
// after a complete tar stream. An aborted parent cannot accidentally turn an
// early EOF into a publishable backup.
func ReceiveCommittedTreeBackupClasses(ctx context.Context, input io.Reader, stage *os.Root, classes []string, maxBytes uint64, nonce string) ([]Root, error) {
	if len(nonce) != 64 {
		return nil, ErrUnsafe
	}
	raw, e := hex.DecodeString(nonce)
	if e != nil || len(raw) != 32 || hex.EncodeToString(raw) != nonce {
		return nil, ErrUnsafe
	}
	return receiveTreeBackupClasses(ctx, input, stage, classes, maxBytes, nonce)
}

func receiveTreeBackupClasses(ctx context.Context, input io.Reader, stage *os.Root, classes []string, maxBytes uint64, nonce string) ([]Root, error) {
	if ctx == nil || input == nil || stage == nil || maxBytes == 0 || maxBytes > 10*1024*1024*1024*1024 || len(classes) == 0 || len(classes) > 4 {
		return nil, ErrUnsafe
	}
	rootInfo, e := stage.Stat(".")
	if e != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0700 {
		return nil, ErrUnsafe
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != uint32(os.Geteuid()) {
		return nil, ErrUnsafe
	}
	absolute, e := filepath.Abs(stage.Name())
	if e != nil {
		return nil, ErrUnsafe
	}
	current, e := os.Lstat(absolute)
	if e != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(rootInfo, current) {
		return nil, ErrUnsafe
	}
	allowed := map[string]bool{}
	for _, class := range classes {
		switch class {
		case "deployment", "redis_data", "certificate_state", "certificate_published":
		default:
			return nil, ErrUnsafe
		}
		if allowed[class] {
			return nil, ErrUnsafe
		}
		allowed[class] = true
	}
	if !allowed["deployment"] {
		return nil, ErrUnsafe
	}
	meta := map[string]map[string]treeStagedMetadata{}
	for class := range allowed {
		meta[class] = map[string]treeStagedMetadata{}
	}
	digest := sha256.New()
	var tarInput io.Reader = input
	if nonce != "" {
		tarInput = io.TeeReader(input, digest)
	}
	reader := tar.NewReader(contextReader{ctx, tarInput})
	var total uint64
	var metadataBytes uint64
	count := 0
	for {
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, ErrUnsafe
		}
		count++
		if count > MaxFiles || h.Uid < 0 || h.Gid < 0 || h.Mode < 0 || h.Mode > 0777 || h.Size < 0 || h.Linkname != "" || h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return nil, ErrUnsafe
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" || len(name) > 4096 || name != path.Clean(name) || !fs.ValidPath(name) || strings.ContainsAny(name, "\\\\\x00\r\n") {
			return nil, ErrUnsafe
		}
		parts := strings.SplitN(name, "/", 2)
		class := parts[0]
		if !allowed[class] {
			return nil, ErrUnsafe
		}
		rel := "."
		if len(parts) == 2 {
			rel = parts[1]
		}
		if _, exists := meta[class][rel]; exists {
			return nil, ErrUnsafe
		}
		isDir := h.Typeflag == tar.TypeDir
		if rel == "." {
			if !isDir || h.Size != 0 {
				return nil, ErrUnsafe
			}
			if e = stage.Mkdir(class, 0700); e != nil {
				return nil, e
			}
		} else {
			parent := path.Dir(rel)
			p, exists := meta[class][parent]
			if !exists || !p.directory {
				return nil, ErrUnsafe
			}
			if isDir {
				if h.Size != 0 {
					return nil, ErrUnsafe
				}
				if e = stage.Mkdir(name, 0700); e != nil {
					return nil, e
				}
			} else {
				size := uint64(h.Size)
				if size > maxBytes-total {
					return nil, ErrUnsafe
				}
				total += size
				f, e := stage.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					return nil, e
				}
				n, copyErr := io.CopyN(f, contextReader{ctx, reader}, h.Size)
				if copyErr == nil && n != h.Size {
					copyErr = io.ErrUnexpectedEOF
				}
				if copyErr == nil {
					copyErr = f.Sync()
				}
				closeErr := f.Close()
				if e = errors.Join(copyErr, closeErr); e != nil {
					return nil, e
				}
			}
		}
		var encoded []byte
		if isDir {
			encoded, e = json.Marshal(Directory{Path: name, Mode: h.Mode, UID: h.Uid, GID: h.Gid})
		} else {
			encoded, e = json.Marshal(Entry{Path: name, Bytes: h.Size, SHA256: strings.Repeat("0", 64), Mode: h.Mode, UID: h.Uid, GID: h.Gid})
		}
		if e != nil || uint64(len(encoded)+1) > uint64(MaxManifest)-metadataBytes {
			return nil, ErrUnsafe
		}
		metadataBytes += uint64(len(encoded) + 1)
		meta[class][rel] = treeStagedMetadata{mode: h.Mode, uid: h.Uid, gid: h.Gid, directory: isDir}
	}
	if nonce != "" {
		var frame [64]byte
		if _, e = io.ReadFull(contextReader{ctx, input}, frame[:]); e != nil {
			return nil, ErrUnsafe
		}
		expectedNonce, _ := hex.DecodeString(nonce)
		if !hmac.Equal(frame[:32], digest.Sum(nil)) || !hmac.Equal(frame[32:], expectedNonce) {
			return nil, ErrUnsafe
		}
		var extra [1]byte
		n, e := contextReader{ctx, input}.Read(extra[:])
		if n != 0 || !errors.Is(e, io.EOF) {
			return nil, ErrUnsafe
		}
	} else {
		// Compatibility helper for isolated in-process staging tests only.
		trailing, e := io.ReadAll(io.LimitReader(contextReader{ctx, input}, 10241))
		if e != nil || len(trailing) > 10240 {
			return nil, ErrUnsafe
		}
		for _, b := range trailing {
			if b != 0 {
				return nil, ErrUnsafe
			}
		}
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	current, e = os.Lstat(absolute)
	if e != nil || !os.SameFile(rootInfo, current) {
		return nil, ErrUnsafe
	}
	ordered := append([]string(nil), classes...)
	sort.Strings(ordered)
	roots := make([]Root, 0, len(ordered))
	for _, class := range ordered {
		root, ok := meta[class]["."]
		if !ok || !root.directory {
			return nil, ErrUnsafe
		}
		for name, v := range meta[class] {
			if v.directory {
				dir := class
				if name != "." {
					dir += "/" + name
				}
				if e = fsutil.SyncDirectory(stage, dir); e != nil {
					return nil, e
				}
			}
		}
		roots = append(roots, Root{Class: class, Directory: filepath.Join(absolute, class), staged: meta[class]})
	}
	if e = fsutil.SyncDirectory(stage, "."); e != nil {
		return nil, e
	}
	return roots, nil
}
