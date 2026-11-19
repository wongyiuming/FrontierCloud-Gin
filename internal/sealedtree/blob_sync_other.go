//go:build !linux

package sealedtree

import "os"

// Until directory durability is explicitly implemented and verified for a
// platform, publishing fails closed there rather than claiming crash safety.
func syncRootDir(_ *os.Root, _ string) error { return ErrBlobIncomplete }
