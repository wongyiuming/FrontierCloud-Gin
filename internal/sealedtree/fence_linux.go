//go:build linux

package sealedtree

import (
	"context"
	"crypto/subtle"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const treeFenceFile = "tree-write.fence"

// InitializeFence creates a new persistent lock identity only for an empty,
// already initialized namespace in a trusted private Master directory. File
// creation, fsync and SQL binding fail closed: an interrupted partial file is
// retained and must never be silently replaced. The root must remain open.
func InitializeFence(ctx context.Context, s *SQLStore, root *os.Root, directory string) (*TreeFence, error) {
	if ctx == nil || !s.valid() || checkFenceDirectory(root, directory) != nil {
		return nil, ErrFenceRequired
	}
	s.fenceMu.Lock()
	defer s.fenceMu.Unlock()
	if s.fence != nil || s.unsafePrototype {
		return nil, ErrFenceRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, ErrFenceRequired
	}
	defer tx.Rollback()
	if err = lockWriter(ctx, tx); err != nil {
		return nil, ErrFenceRequired
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return nil, ErrFenceRequired
	}
	for _, table := range []string{"sealed_tree_records", "sealed_tree_placements", "sealed_tree_aliases", "sealed_tree_revocations", "sealed_tree_facts", "sealed_tree_blob_ids", "sealed_tree_operation_ids", "sealed_tree_pending_files", "sealed_tree_pending_facts", "sealed_tree_fence"} {
		var n int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil || n != 0 {
			return nil, ErrFenceRequired
		}
	}
	var reserved int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids`).Scan(&reserved); err != nil || reserved != 1 {
		return nil, ErrFenceRequired
	}
	id, err := NewMasterSecret()
	if err != nil {
		return nil, ErrFenceRequired
	}
	defer clear(id)
	file, err := root.OpenFile(treeFenceFile, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrFenceRequired
	}
	defer file.Close()
	if err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, ErrFenceRequired
	}
	defer unlockFenceFile(file)
	n, writeErr := file.Write(id)
	syncErr := file.Sync()
	if writeErr != nil || n != len(id) || syncErr != nil || syncRootDir(root, ".") != nil {
		return nil, ErrFenceRequired
	}
	f := &TreeFence{store: s, root: root, directory: directory}
	copy(f.id[:], id)
	info, err := file.Stat()
	if err != nil {
		return nil, ErrFenceRequired
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, ErrFenceRequired
	}
	f.device = uint64(stat.Dev)
	f.inode = stat.Ino
	if err = f.checkFile(file); err != nil {
		return nil, ErrFenceRequired
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_fence(singleton,fence_tag) VALUES(1,?)`, f.tag()); err != nil {
		return nil, ErrFenceRequired
	}
	if err = tx.Commit(); err != nil {
		return nil, ErrFenceRequired
	}
	s.fence = f
	return f, nil
}

// OpenFence attaches an existing file and database binding without creating
// either. Every process must use the same trusted filesystem inode; the caller
// must also ensure no older/unfenced runtime can write the namespace.
func OpenFence(ctx context.Context, s *SQLStore, root *os.Root, directory string) (*TreeFence, error) {
	if ctx == nil || !s.valid() || checkFenceDirectory(root, directory) != nil {
		return nil, ErrFenceRequired
	}
	s.fenceMu.Lock()
	defer s.fenceMu.Unlock()
	if s.fence != nil || s.unsafePrototype {
		return nil, ErrFenceRequired
	}
	file, err := root.OpenFile(treeFenceFile, os.O_RDWR, 0)
	if err != nil {
		return nil, ErrFenceRequired
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() != 32 {
		return nil, ErrFenceRequired
	}
	id := make([]byte, 32)
	if _, err = file.ReadAt(id, 0); err != nil {
		clear(id)
		return nil, ErrFenceRequired
	}
	defer clear(id)
	f := &TreeFence{store: s, root: root, directory: directory}
	copy(f.id[:], id)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, ErrFenceRequired
	}
	f.device = uint64(stat.Dev)
	f.inode = stat.Ino
	if err = f.checkFile(file); err != nil {
		return nil, ErrFenceRequired
	}
	lease, err := f.acquire(ctx, false)
	if err != nil {
		return nil, err
	}
	lease.Release()
	s.fence = f
	return f, nil
}

func (f *TreeFence) checkFile(file *os.File) error {
	if f == nil || f.root == nil || file == nil || checkFenceDirectory(f.root, f.directory) != nil {
		return ErrFenceChanged
	}
	pathInfo, err := f.root.Lstat(treeFenceFile)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0077 != 0 || pathInfo.Mode().Perm()&0600 != 0600 || pathInfo.Size() != 32 {
		return ErrFenceChanged
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 || opened.Mode().Perm()&0600 != 0600 || opened.Size() != 32 {
		return ErrFenceChanged
	}
	st, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || uint64(st.Dev) != f.device || st.Ino != f.inode {
		return ErrFenceChanged
	}
	data := make([]byte, 32)
	defer clear(data)
	if n, err := file.ReadAt(data, 0); err != nil || n != len(data) {
		return ErrFenceChanged
	}
	if subtle.ConstantTimeCompare(data, f.id[:]) != 1 {
		return ErrFenceChanged
	}
	return nil
}

func checkFenceDirectory(root *os.Root, directory string) error {
	if root == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || checkPrivateDirectory(root) != nil {
		return ErrFenceChanged
	}
	pathInfo, err := os.Lstat(directory)
	if err != nil || !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return ErrFenceChanged
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(pathInfo, opened) {
		return ErrFenceChanged
	}
	return nil
}

func (f *TreeFence) acquire(ctx context.Context, exclusive bool) (*TreeLease, error) {
	if f == nil || f.root == nil || ctx == nil {
		return nil, ErrFenceRequired
	}
	file, err := f.root.OpenFile(treeFenceFile, os.O_RDWR, 0)
	if err != nil {
		return nil, ErrFenceChanged
	}
	locked := false
	defer func() {
		if !locked {
			_ = file.Close()
		}
	}()
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		err = unix.Flock(int(file.Fd()), mode|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return nil, ErrFenceChanged
		}
		timer := time.NewTimer(15 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err = f.checkFile(file); err != nil {
		unlockFenceFile(file)
		return nil, ErrFenceChanged
	}
	generation, err := f.databaseGeneration(ctx)
	if err != nil || f.checkFile(file) != nil {
		unlockFenceFile(file)
		return nil, ErrFenceChanged
	}
	if err = ctx.Err(); err != nil {
		unlockFenceFile(file)
		return nil, err
	}
	locked = true
	return &TreeLease{fence: f, file: file, generation: generation, exclusive: exclusive}, nil
}

func unlockFenceFile(file *os.File) {
	if file != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
	}
}
