//go:build !linux

package sealedtree

import (
	"context"
	"os"
)

// No platform silently falls back to an in-process mutex as a tree fence.
func InitializeFence(context.Context, *SQLStore, *os.Root, string) (*TreeFence, error) {
	return nil, ErrFenceRequired
}
func OpenFence(context.Context, *SQLStore, *os.Root, string) (*TreeFence, error) {
	return nil, ErrFenceRequired
}
func (*TreeFence) checkFile(*os.File) error                          { return ErrFenceRequired }
func (*TreeFence) acquire(context.Context, bool) (*TreeLease, error) { return nil, ErrFenceRequired }
func unlockFenceFile(*os.File)                                       {}
