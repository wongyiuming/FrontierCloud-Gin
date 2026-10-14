package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

func checkRestoreFilesystemCapacity(roots map[string]string, entries []recovery.Entry, free func(string) (uint64, error), filesystem func(string) (string, error)) error {
	type capacity struct {
		path         string
		growth, peak uint64
	}
	budgets := map[string]*capacity{}
	for _, entry := range entries {
		class, relative, ok := strings.Cut(entry.Path, "/")
		if !ok || roots[class] == "" || entry.Bytes < 0 {
			return recovery.ErrUnsafe
		}
		root, e := os.OpenRoot(roots[class])
		if e != nil {
			return e
		}
		info, e := root.Lstat(relative)
		var current uint64
		if e == nil {
			if !info.Mode().IsRegular() {
				root.Close()
				return recovery.ErrUnsafe
			}
			current = diskAllocated(info)
		} else if !os.IsNotExist(e) {
			root.Close()
			return e
		}
		parent := path.Dir(relative)
		for {
			info, e = root.Lstat(parent)
			if e == nil {
				if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
					root.Close()
					return recovery.ErrUnsafe
				}
				break
			}
			if !os.IsNotExist(e) || parent == "." {
				root.Close()
				return e
			}
			parent = path.Dir(parent)
		}
		root.Close()
		destination := filepath.Join(roots[class], parent)
		id, e := filesystem(destination)
		if e != nil {
			return e
		}
		b := budgets[id]
		if b == nil {
			b = &capacity{path: destination}
			budgets[id] = b
		}
		size := uint64(entry.Bytes)
		if size > current {
			if b.growth > ^uint64(0)-(size-current) {
				return recovery.ErrUnsafe
			}
			b.growth += size - current
		}
		if size > b.peak {
			b.peak = size
		}
	}
	for _, b := range budgets {
		available, e := free(b.path)
		if e != nil {
			return e
		}
		if b.growth > ^uint64(0)-b.peak-(512<<20) || available < b.growth+b.peak+(512<<20) {
			return errors.New("in-place state filesystem lacks cumulative growth, temporary-copy capacity and reserve; no restoration performed")
		}
	}
	return nil
}

func checkMySQLRecoveryCredential(roots map[string]string, entries []recovery.Entry) error {
	found := map[string]bool{}
	for _, entry := range entries {
		if entry.Path != "runtime_secrets/mysql_root_password" && entry.Path != "runtime_secrets/mysql_password" {
			continue
		}
		root, e := os.OpenRoot(roots["runtime_secrets"])
		if e != nil {
			return e
		}
		defer root.Close()
		_, name, _ := strings.Cut(entry.Path, "/")
		info, e := root.Lstat(name)
		if e != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
			return errors.New("current MySQL credential unavailable; no state replaced")
		}
		f, e := root.Open(name)
		if e != nil {
			return e
		}
		h := sha256.New()
		_, e = io.Copy(h, io.LimitReader(f, 4097))
		e = errors.Join(e, f.Close())
		if e != nil {
			return e
		}
		if hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
			return errors.New("MySQL credential drift requires separately coordinated credential recovery; no state replaced")
		}
		found[name] = true
	}
	if found["mysql_root_password"] && found["mysql_password"] {
		return nil
	}
	return errors.New("archive lacks MySQL credential evidence; no state replaced")
}
