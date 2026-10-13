package resourceinventory

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"os"
	"strings"
)

// IdleLeaseAt observes a zero-byte native top-level lease without creating,
// writing or unlinking it. The exclusive probe is released before returning;
// this observation cannot substitute for a final held retirement fence.
func IdleLeaseAt(ctx context.Context, root *os.Root, entry Entry) error {
	if root == nil || entry.Kind != "regular" || entry.LogicalBytes != 0 || entry.Path == "" || entry.Path == "." || entry.Path == ".." || strings.ContainsAny(entry.Path, "/\\\x00:") {
		return ErrChanged
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	before, e := root.Lstat(entry.Path)
	if e != nil {
		return e
	}
	if !before.Mode().IsRegular() || before.Size() != 0 || before.ModTime().UnixNano() != entry.ModifiedNS {
		return ErrChanged
	}
	file, e := openContentFile(root, entry.Path)
	if e != nil {
		return e
	}
	opened, e := file.Stat()
	if e != nil || !sameContentInfo(opened, before) {
		file.Close()
		return ErrChanged
	}
	release, e := filelease.Try(file, true)
	if e != nil {
		return e
	}
	defer release()
	if e = ctx.Err(); e != nil {
		return e
	}
	now, e := root.Lstat(entry.Path)
	if e != nil || !sameContentInfo(now, before) {
		return ErrChanged
	}
	return nil
}
