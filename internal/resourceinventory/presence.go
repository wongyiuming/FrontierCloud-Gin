package resourceinventory

import (
	"context"
	"errors"
	"os"
	"path"
	"strings"
	"unicode/utf8"
)

type Presence struct {
	State        string `json:"state"`
	LogicalBytes int64  `json:"logical_bytes,omitempty"`
	ModifiedNS   int64  `json:"modified_ns,omitempty"`
}

// PresenceAt checks every ancestor without following symlinks or reading bytes.
// This is an observation, not an immutable byte/version proof or deletion grant.
func PresenceAt(ctx context.Context, root *os.Root, name string) (Presence, error) {
	if root == nil || name == "." || name == ".." || !utf8.ValidString(name) || len(name) > MaxPathBytes || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00:") {
		return Presence{State: "invalid_path"}, nil
	}
	parts := strings.Split(name, "/")
	if len(parts) > MaxDepth {
		return Presence{State: "invalid_path"}, nil
	}
	pinned := []os.FileInfo{}
	names := []string{}
	result := Presence{State: "present"}
	for i := range parts {
		if e := ctx.Err(); e != nil {
			return Presence{}, e
		}
		current := strings.Join(parts[:i+1], "/")
		info, e := root.Lstat(current)
		if errors.Is(e, os.ErrNotExist) {
			result.State = "missing"
			break
		}
		if e != nil {
			return Presence{State: "unverified"}, nil
		}
		if info.Mode()&os.ModeSymlink != 0 || i < len(parts)-1 && !info.IsDir() || i == len(parts)-1 && !info.Mode().IsRegular() {
			result.State = "unsupported"
			break
		}
		pinned = append(pinned, info)
		names = append(names, current)
		if i == len(parts)-1 {
			result.LogicalBytes = info.Size()
			result.ModifiedNS = info.ModTime().UnixNano()
		}
	}
	for i, name := range names {
		now, e := root.Lstat(name)
		if e != nil || !os.SameFile(now, pinned[i]) || now.Mode() != pinned[i].Mode() || now.Size() != pinned[i].Size() || !now.ModTime().Equal(pinned[i].ModTime()) {
			return Presence{State: "changed"}, nil
		}
	}
	return result, nil
}
