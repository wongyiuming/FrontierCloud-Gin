//go:build !linux

package sealedtree

import "os"

// The selected Owner receiver is Linux-only. Preserve existing portable callers
// while refusing a final-component symlink on non-Linux systems.
func blobOpen(root *os.Root, name string, flags int, mode os.FileMode) (*os.File, error) {
	if flags&os.O_CREATE == 0 {
		if info, err := root.Lstat(name); err != nil || !info.Mode().IsRegular() {
			return nil, ErrBlobIncomplete
		}
	}
	return root.OpenFile(name, flags, mode)
}
func blobLink(root *os.Root, source, target string, expected os.FileInfo, allowExisting bool) error {
	sourceFile, e := blobOpen(root, source, os.O_RDONLY, 0)
	if e != nil {
		return ErrBlobIncomplete
	}
	info, e := sourceFile.Stat()
	sourceFile.Close()
	if e != nil || !os.SameFile(expected, info) {
		return ErrBlobIncomplete
	}
	if e = root.Link(source, target); e != nil && !(allowExisting && os.IsExist(e)) {
		return ErrBlobIncomplete
	}
	f, e := blobOpen(root, target, os.O_RDONLY, 0)
	if e != nil {
		return ErrBlobIncomplete
	}
	defer f.Close()
	info, e = f.Stat()
	if e != nil || !allowExisting && !os.SameFile(expected, info) {
		return ErrBlobIncomplete
	}
	return nil
}
