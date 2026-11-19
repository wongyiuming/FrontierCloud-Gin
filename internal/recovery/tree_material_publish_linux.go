//go:build linux

package recovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Keep the tree extraction and its eventual no-replace publication on the
// same checked parent, even if someone changes the parent path during a copy.
func openTreeMaterialStage(target string) (root *os.Root, publish func(context.Context) error, closeParent func(), err error) {
	target, err = filepath.Abs(target)
	if err != nil || target == string(os.PathSeparator) {
		return nil, nil, nil, ErrUnsafe
	}
	parentPath, targetName := filepath.Dir(target), filepath.Base(target)
	before, err := os.Lstat(parentPath)
	if err != nil || !before.IsDir() || before.Mode().Perm()&0022 != 0 {
		return nil, nil, nil, ErrUnsafe
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, nil, nil, ErrUnsafe
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		if err != nil {
			_ = parent.Close()
		}
	}()
	checkParent := func() error {
		opened, openErr := parent.Stat(".")
		current, pathErr := os.Lstat(parentPath)
		if openErr != nil || pathErr != nil || current.Mode() != before.Mode() ||
			!os.SameFile(before, opened) || !os.SameFile(before, current) {
			return ErrUnsafe
		}
		return nil
	}
	if err = checkParent(); err != nil {
		return nil, nil, nil, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, nil, nil, err
	}
	stageName := ".fc-restore-" + hex.EncodeToString(nonce[:])
	if err = parent.Mkdir(stageName, 0700); err != nil {
		return nil, nil, nil, err
	}
	stageInfo, err := parent.Lstat(stageName)
	if err != nil || !stageInfo.IsDir() || stageInfo.Mode().Perm() != 0700 {
		return nil, nil, nil, ErrUnsafe
	}
	root, err = parent.OpenRoot(stageName)
	if err != nil {
		return nil, nil, nil, err
	}
	openedStage, err := root.Stat(".")
	if err != nil || !os.SameFile(stageInfo, openedStage) {
		_ = root.Close()
		return nil, nil, nil, ErrUnsafe
	}
	return root, func(ctx context.Context) error {
		if err := checkParent(); err != nil {
			return err
		}
		current, err := parent.Lstat(stageName)
		if err != nil || current.Mode() != stageInfo.Mode() || !os.SameFile(stageInfo, current) {
			return ErrUnsafe
		}
		directory, err := parent.Open(".")
		if err != nil {
			return err
		}
		defer directory.Close()
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = unix.Renameat2(int(directory.Fd()), stageName, int(directory.Fd()), targetName, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err = directory.Sync(); err != nil {
			return err
		}
		current, err = parent.Lstat(targetName)
		if err != nil || !os.SameFile(stageInfo, current) {
			return ErrUnsafe
		}
		return checkParent()
	}, func() { _ = parent.Close() }, nil
}
