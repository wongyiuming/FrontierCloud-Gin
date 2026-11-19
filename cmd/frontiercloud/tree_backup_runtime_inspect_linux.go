//go:build linux

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
)

// Read-only, no DB/key opens or service startup. Production callers must still
// independently authorize capture and check every reply against a fresh nonce.
func treeBackupRuntimeInspect(args []string, out io.Writer) error {
	return inspectTreeBackupRuntimePaths(args, out, [3]string{"/fc-tree-data", "/fc-tree-secrets", "/fc-tree-tmp"})
}

func inspectTreeBackupRuntimePaths(args []string, out io.Writer, paths [3]string) error {
	if len(args) != 1 || len(args[0]) != 64 {
		return errors.New("invalid tree backup inspection nonce")
	}
	b, e := hex.DecodeString(args[0])
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != args[0] {
		return errors.New("invalid tree backup inspection nonce")
	}
	proof := runtimefacts.TreeBackupRuntime{Nonce: args[0], UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	raw, e := os.ReadFile("/proc/self/uid_map")
	if e != nil || len(raw) > 1024 {
		return errors.New("runtime uid map unavailable")
	}
	proof.UIDMap = strings.TrimSpace(string(raw))
	for _, v := range []struct {
		path string
		out  *runtimefacts.TreeBackupMount
	}{{paths[0], &proof.Data}, {paths[1], &proof.Secrets}, {paths[2], &proof.Scratch}} {
		if !filepath.IsAbs(v.path) {
			return errors.New("invalid runtime mount")
		}
		before, err := os.Lstat(v.path)
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return errors.New("runtime mount unavailable")
		}
		root, err := os.OpenRoot(v.path)
		if err != nil {
			return errors.New("runtime mount unavailable")
		}
		actual, err := root.Stat(".")
		root.Close()
		if err != nil || !os.SameFile(before, actual) {
			return errors.New("runtime mount changed")
		}
		st, ok := actual.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("runtime mount identity unavailable")
		}
		*v.out = runtimefacts.TreeBackupMount{Device: uint64(st.Dev), Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode}
	}
	return json.NewEncoder(out).Encode(proof)
}
