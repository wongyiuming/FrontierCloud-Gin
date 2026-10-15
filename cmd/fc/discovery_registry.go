package main

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Remember verified paths independently of transient Docker labels. Root uses
// the host registry; other Docker operators retain their own private registry.
func rememberDeployment(ctx context.Context, directory string) error {
	registry := "/etc/frontiercloud/foc-deployments"
	lock := "/usr/local/lib/frontiercloud/foc/.install-lock"
	if os.Geteuid() != 0 {
		base := os.Getenv("XDG_STATE_HOME")
		if base == "" {
			home, e := os.UserHomeDir()
			if e != nil {
				return e
			}
			base = filepath.Join(home, ".local", "state")
		}
		if !filepath.IsAbs(base) {
			return errors.New("absolute user state directory required")
		}
		parent := filepath.Join(base, "frontiercloud")
		if e := os.MkdirAll(parent, 0700); e != nil {
			return e
		}
		registry = filepath.Join(parent, "foc-deployments")
		lock = filepath.Join(parent, ".install-lock")
	}
	return persistDeployment(ctx, registry, lock, directory)
}

func persistDeployment(ctx context.Context, registry, lock, directory string) (err error) {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := os.Mkdir(lock, 0700); e != nil {
		return errors.New("deployment registry installation is active or interrupted")
	}
	defer func() { err = errors.Join(err, os.Remove(lock)) }()
	info, e := os.Lstat(registry)
	var data []byte
	if e == nil {
		if !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return errors.New("unsafe deployment registry")
		}
		data, e = os.ReadFile(registry)
	} else if os.IsNotExist(e) {
		e = nil
	}
	if e != nil {
		return e
	}
	entries := map[string]bool{}
	for _, entry := range strings.Split(string(data), "\n") {
		if entry != "" {
			entries[entry] = true
		}
	}
	if strings.ContainsAny(directory, "\r\n\x00") || !filepath.IsAbs(directory) {
		return errors.New("invalid registered deployment path")
	}
	entries[directory] = true
	var paths []string
	for entry := range entries {
		paths = append(paths, entry)
	}
	sort.Strings(paths)
	f, e := os.CreateTemp(filepath.Dir(registry), ".foc-registry-")
	if e != nil {
		return e
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	_, e = f.WriteString(strings.Join(paths, "\n") + "\n")
	if e == nil {
		e = f.Chmod(0644)
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = os.Rename(temporary, registry); e != nil {
		return e
	}
	root, e := os.OpenRoot(filepath.Dir(registry))
	if e != nil {
		return e
	}
	defer root.Close()
	return fsutil.SyncDirectory(root, ".")
}
