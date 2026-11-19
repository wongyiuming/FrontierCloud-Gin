package maintenance

import (
	"context"
	"errors"
	"os"
)

// TreeRecoveryHold keeps ordinary runtime startup and resume closed across
// tree recovery phases. It never contains keys or authorizes recovery itself.
const TreeRecoveryHold = ".frontiercloud-tree-recovery-hold"
const treeRecoveryHoldPrefix = "frontiercloud-tree-recovery-hold-v1\n"

// TreeRecoveryHeld detects any object at the reserved name, including malformed
// files and symlinks. Callers making state changes must also hold the native leases.
func (g *Gate) TreeRecoveryHeld() (bool, error) {
	if g == nil || g.root == nil {
		return true, ErrState
	}
	_, err := g.root.Lstat(TreeRecoveryHold)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	return true, nil
}

func validTreeRecoveryBinding(binding string) bool {
	if len(binding) != 64 {
		return false
	}
	for _, c := range binding {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// HoldTreeRecovery arms a persistent hold bound to a caller-verified recovery
// plan digest. It holds both native leases throughout publication; it does not
// verify the plan, restore data, or authorize a later release. Existing holds
// can be retried only with exactly the same binding. No release is provided.
func (g *Gate) HoldTreeRecovery(ctx context.Context, binding string) error {
	if g == nil || g.root == nil || ctx == nil || !validTreeRecoveryBinding(binding) {
		return ErrState
	}
	releaseControl, checkControl, err := g.leaseChecked(ctx, controlLock, true)
	if err != nil {
		return err
	}
	defer releaseControl()
	enabled, err := g.Enabled()
	if err != nil || !enabled {
		return ErrState
	}
	marker, err := g.root.Lstat(Marker)
	if err != nil || !privateSingleLink(marker) {
		return ErrState
	}
	releaseRuntime, checkRuntime, err := g.leaseChecked(ctx, runtimeLock, true)
	if err != nil {
		return err
	}
	defer releaseRuntime()
	check := func() error {
		if ctx.Err() != nil || checkControl() != nil || checkRuntime() != nil {
			return ErrState
		}
		pathInfo, e := os.Lstat(g.root.Name())
		openedRoot, rootErr := g.root.Stat(".")
		if e != nil || rootErr != nil || !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(pathInfo, openedRoot) {
			return ErrState
		}
		for _, name := range []string{controlLock, runtimeLock} {
			info, e := g.root.Lstat(name)
			if e != nil || !privateSingleLink(info) {
				return ErrState
			}
		}
		current, e := g.root.Lstat(Marker)
		if e != nil || !privateSingleLink(current) || !os.SameFile(marker, current) {
			return ErrState
		}
		if enabled, e := g.Enabled(); e != nil || !enabled {
			return ErrState
		}
		return nil
	}
	if err = check(); err != nil {
		return err
	}
	return g.publishTreeRecoveryHold(ctx, []byte(treeRecoveryHoldPrefix+binding+"\n"), check)
}
