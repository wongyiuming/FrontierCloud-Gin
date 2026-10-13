package resourceinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
	"strings"
	"unicode/utf8"
)

type ContentObservation struct {
	Path       string `json:"path"`
	Bytes      int64  `json:"size_bytes"`
	ModifiedNS int64  `json:"modified_ns"`
	SHA256     string `json:"sha256"`
}

type contentReadAdmissionKey struct{}

// WithContentReadAdmission lets an authenticated observation yield between
// bounded reads while preserving its pinned file and incremental hash state.
func WithContentReadAdmission(ctx context.Context, admit func() error) context.Context {
	return context.WithValue(ctx, contentReadAdmissionKey{}, admit)
}

func admitContentRead(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if admit, ok := ctx.Value(contentReadAdmissionKey{}).(func() error); ok && admit != nil {
		return admit()
	}
	return nil
}

// ContentAt observes a caller-authorized managed path with one fixed buffer.
// It is not a frozen version, writer fence, migration or deletion authorization.
func ContentAt(ctx context.Context, root *os.Root, name string, expected int64) (ContentObservation, error) {
	var result ContentObservation
	if root == nil || expected < 0 || name == "." || name == ".." || !utf8.ValidString(name) || len(name) > MaxPathBytes || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00:") {
		return result, os.ErrInvalid
	}
	if err := admitContentRead(ctx); err != nil {
		return result, err
	}
	parts := strings.Split(name, "/")
	if len(parts) > MaxDepth {
		return result, ErrLimit
	}
	names := []string{}
	infos := []os.FileInfo{}
	for i := range parts {
		if e := ctx.Err(); e != nil {
			return result, e
		}
		current := strings.Join(parts[:i+1], "/")
		info, e := root.Lstat(current)
		if e != nil {
			return result, e
		}
		if info.Mode()&os.ModeSymlink != 0 || i < len(parts)-1 && !info.IsDir() || i == len(parts)-1 && (!info.Mode().IsRegular() || info.Size() != expected) {
			return result, ErrChanged
		}
		names = append(names, current)
		infos = append(infos, info)
	}
	file, e := openContentFile(root, name)
	if e != nil {
		return result, e
	}
	defer file.Close()
	before, e := file.Stat()
	if e != nil || !sameContentInfo(before, infos[len(infos)-1]) {
		return result, ErrChanged
	}
	digest := sha256.New()
	buffer := make([]byte, 64<<10)
	remaining := expected
	for remaining > 0 {
		if e = admitContentRead(ctx); e != nil {
			return result, e
		}
		length := int64(len(buffer))
		if remaining < length {
			length = remaining
		}
		n, e := io.ReadFull(file, buffer[:length])
		if e != nil {
			return result, e
		}
		digest.Write(buffer[:n])
		remaining -= int64(n)
	}
	if e = ctx.Err(); e != nil {
		return result, e
	}
	n, e := file.Read(buffer[:1])
	if n != 0 || e != io.EOF {
		return result, ErrChanged
	}
	after, e := file.Stat()
	if e != nil || !sameContentInfo(after, before) {
		return result, ErrChanged
	}
	for i, current := range names {
		now, e := root.Lstat(current)
		if e != nil || !sameContentInfo(now, infos[i]) {
			return result, ErrChanged
		}
	}
	return ContentObservation{Path: name, Bytes: expected, ModifiedNS: before.ModTime().UnixNano(), SHA256: hex.EncodeToString(digest.Sum(nil))}, nil
}
func sameContentInfo(now, before os.FileInfo) bool {
	return now != nil && before != nil && os.SameFile(now, before) && now.Mode() == before.Mode() && now.Size() == before.Size() && now.ModTime().Equal(before.ModTime())
}

func openContentChecked(root *os.Root, name string, flags int) (*os.File, error) {
	before, e := root.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() {
		return nil, ErrChanged
	}
	file, e := root.OpenFile(name, flags, 0)
	if e != nil {
		return nil, e
	}
	actual, e := file.Stat()
	if e != nil || !sameContentInfo(actual, before) {
		file.Close()
		return nil, ErrChanged
	}
	now, e := root.Lstat(name)
	if e != nil || !sameContentInfo(now, before) {
		file.Close()
		return nil, ErrChanged
	}
	return file, nil
}
