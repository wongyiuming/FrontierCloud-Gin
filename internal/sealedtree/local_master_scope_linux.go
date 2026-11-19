//go:build linux

package sealedtree

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"os"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// localMasterScope exists only while maintenance, Owner and tree exclusive
// leases are held, in that order. It must not escape the callback.
type localMasterScope struct {
	ctx         context.Context
	s           *SQLStore
	mediaRoot   *os.Root
	masterID    string
	guard       func(*sql.Tx) error
	checkFences func() error
}

func withLocalMasterScope(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, s *SQLStore, treeRoot, mediaRoot *os.Root, ownerFence *ownerfence.Fence, nodeVault *vault.Vault, masterID string, fn func(*localMasterScope) error) error {
	if ctx == nil || gate == nil || s == nil || treeRoot == nil || mediaRoot == nil || ownerFence == nil || nodeVault == nil || !s.valid() || !lowerHex(masterID, 32) || fn == nil {
		return ErrInvalid
	}
	return gate.InspectSQLite(ctx, dataRoot, databasePath, func(held context.Context, check func() error) error {
		expectedMedia, e := filepath.Abs(filepath.Join(dataRoot, "media"))
		if e != nil {
			return ErrInvalid
		}
		actualMedia, e := filepath.Abs(mediaRoot.Name())
		if e != nil || filepath.Clean(actualMedia) != filepath.Clean(expectedMedia) {
			return ErrFenceRequired
		}
		named, e := os.Lstat(expectedMedia)
		if e != nil || !named.IsDir() || named.Mode()&os.ModeSymlink != 0 {
			return ErrFenceRequired
		}
		opened, e := mediaRoot.Stat(".")
		if e != nil || !os.SameFile(named, opened) {
			return ErrFenceRequired
		}
		owner, e := ownerFence.Acquire(held, true)
		if e != nil {
			return ErrFenceRequired
		}
		defer owner.Release()
		binding, e := owner.Binding(held)
		if e != nil {
			return ErrFenceRequired
		}
		s.fenceMu.RLock()
		fence := s.fence
		s.fenceMu.RUnlock()
		if fence == nil || fence.store != s || recoveryFenceLocation(dataRoot, treeRoot, fence.directory) != nil {
			return ErrFenceRequired
		}
		want, e := treeRoot.Stat(".")
		if e != nil {
			return ErrFenceRequired
		}
		got, e := fence.root.Stat(".")
		if e != nil || !os.SameFile(want, got) {
			return ErrFenceRequired
		}
		lease, e := fence.acquire(held, true)
		if e != nil {
			return e
		}
		defer lease.Release()
		guard := func(tx *sql.Tx) error {
			if check() != nil || owner.Check(held) != nil || fence.checkFile(lease.file) != nil || s.verifyRoot(held, tx) != nil {
				return ErrFenceRequired
			}
			current, err := owner.Binding(held)
			if err != nil || !hmac.Equal([]byte(current), []byte(binding)) {
				return ErrFenceRequired
			}
			var ownerTag, treeTag, mainPath string
			if tx.QueryRowContext(held, `SELECT fence_tag FROM sealed_tree_owner_fence WHERE singleton=1`).Scan(&ownerTag) != nil || !hmac.Equal([]byte(ownerTag), []byte(binding)) {
				return ErrFenceRequired
			}
			if tx.QueryRowContext(held, `SELECT fence_tag FROM sealed_tree_fence WHERE singleton=1`).Scan(&treeTag) != nil || !hmac.Equal([]byte(treeTag), []byte(fence.tag())) {
				return ErrFenceRequired
			}
			if tx.QueryRowContext(held, `SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&mainPath) != nil {
				return ErrFenceRequired
			}
			a, e1 := filepath.Abs(mainPath)
			b, e2 := filepath.Abs(databasePath)
			if e1 != nil || e2 != nil || filepath.Clean(a) != filepath.Clean(b) {
				return ErrFenceRequired
			}
			first, e1 := os.Stat(a)
			second, e2 := os.Lstat(b)
			if e1 != nil || e2 != nil || !second.Mode().IsRegular() || second.Mode()&os.ModeSymlink != 0 || !os.SameFile(first, second) {
				return ErrFenceRequired
			}
			if _, err = recoveryMasterBinding(held, tx, s, treeRoot, nodeVault, masterID); err != nil {
				return err
			}
			currentMedia, err := os.Lstat(expectedMedia)
			if err != nil || !currentMedia.IsDir() || currentMedia.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, currentMedia) {
				return ErrFenceRequired
			}
			return held.Err()
		}
		checkFences := func() error {
			if check() != nil || owner.Check(held) != nil || fence.checkFile(lease.file) != nil {
				return ErrFenceRequired
			}
			return held.Err()
		}
		return fn(&localMasterScope{ctx: held, s: s, mediaRoot: mediaRoot, masterID: masterID, guard: guard, checkFences: checkFences})
	})
}
