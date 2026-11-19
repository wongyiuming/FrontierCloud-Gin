//go:build linux

package sealedtree

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

const treeKeyFile = MasterKeyFile

// Key access requires a trusted directory exclusively owned by the Master
// process. This check alone does not establish backup, recovery, migration or
// startup readiness, and must not be used on an untrusted resource node.
func checkPrivateDirectory(root *os.Root) error {
	if root == nil {
		return ErrInvalid
	}
	f, err := root.Open(".")
	if err != nil {
		return ErrInvalid
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private tree key directory metadata: %w", ErrInvalid)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("private tree key directory owner: %w", ErrInvalid)
	}
	return nil
}

func openPrivateTreeDirectory(name string) (*os.Root, error) {
	before, err := os.Lstat(name)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, ErrFenceRequired
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, ErrFenceRequired
	}
	after, err := root.Stat(".")
	current, pathErr := os.Lstat(name)
	if err != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, current) || checkPrivateDirectory(root) != nil {
		root.Close()
		return nil, ErrFenceRequired
	}
	return root, nil
}

// CreateTreeSecretFile creates a dedicated random secret only in an explicitly
// new, private Master key directory. O_EXCL prevents replacing any old key;
// a partial file is retained after a failed write so restart fails closed.
// Callers must first prove a new namespace and provide separate recovery keys.
func CreateTreeSecretFile(root *os.Root) ([]byte, error) {
	if err := checkPrivateDirectory(root); err != nil {
		return nil, err
	}
	key, err := NewMasterSecret()
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile(treeKeyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		clear(key)
		return nil, ErrInvalid
	}
	n, writeErr := f.Write(key)
	info, statErr := f.Stat()
	private := false
	if statErr == nil && info.Mode().IsRegular() && info.Mode().Perm()&0077 == 0 && info.Mode().Perm()&0400 != 0 && info.Size() == 32 {
		stat, ok := info.Sys().(*syscall.Stat_t)
		private = ok && stat.Uid == uint32(os.Geteuid())
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || n != len(key) || !private || syncErr != nil || closeErr != nil {
		clear(key)
		return nil, fmt.Errorf("private tree key file write or metadata: %w", ErrInvalid)
	}
	if syncRootDir(root, ".") != nil {
		clear(key)
		return nil, fmt.Errorf("private tree key directory fsync: %w", ErrInvalid)
	}
	return key, nil
}

// OpenTreeSecretFile loads an existing key without creating one. A missing,
// truncated, symlinked, incorrectly owned or nonprivate file fails closed.
// Callers must clear the returned bytes after deriving the in-memory tree.
func OpenTreeSecretFile(root *os.Root) ([]byte, error) {
	if err := checkPrivateDirectory(root); err != nil {
		return nil, err
	}
	info, err := root.Lstat(treeKeyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0400 == 0 || info.Size() != 32 {
		return nil, ErrInvalid
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, ErrInvalid
	}
	f, err := root.Open(treeKeyFile)
	if err != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 || opened.Mode().Perm()&0400 == 0 || opened.Size() != 32 {
		return nil, ErrInvalid
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || openedStat.Uid != uint32(os.Geteuid()) {
		return nil, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(data) != 32 {
		clear(data)
		return nil, ErrInvalid
	}
	var nonzero byte
	for _, value := range data {
		nonzero |= value
	}
	if nonzero == 0 {
		clear(data)
		return nil, ErrInvalid
	}
	return data, nil
}
