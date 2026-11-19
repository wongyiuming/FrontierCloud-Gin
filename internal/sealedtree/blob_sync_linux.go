//go:build linux

package sealedtree

import "os"

func syncRootDir(root *os.Root, name string) error {
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.IsDir() {
		return ErrBlobIncomplete
	}
	return f.Sync()
}
