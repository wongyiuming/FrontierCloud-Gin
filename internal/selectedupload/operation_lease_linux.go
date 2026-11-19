//go:build linux

package selectedupload

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

var errOperationLease = errors.New("selected upload operation lease unavailable")

// operationLease serializes all staging, recovery and cleanup of one
// operation across cooperating processes. Its persistent lock inode must never
// be removed while a writer can use it. The caller also holds the independently
// acquired Owner policy lease; this does not replace that policy fence.
type operationLease struct {
	root      *os.Root
	file      *os.File
	directory *os.File
	name      string
	release   func()
	once      sync.Once
}

func validOperationID(id string) bool {
	if len(id) != 64 {
		return false
	}
	raw, err := hex.DecodeString(id)
	return err == nil && hex.EncodeToString(raw) == id
}

func syncOperationDir(root *os.Root, name string) error {
	d, err := root.Open(name)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func acquireOperationLease(ctx context.Context, root *os.Root, op string) (*operationLease, error) {
	if ctx == nil || root == nil || !validOperationID(op) || ctx.Err() != nil {
		return nil, errOperationLease
	}
	const dir = ".selected-upload-locks"
	if err := root.MkdirAll(dir, 0700); err != nil {
		return nil, errOperationLease
	}
	info, err := root.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errOperationLease
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || syncOperationDir(root, ".") != nil {
		return nil, errOperationLease
	}
	directory, err := root.Open(dir)
	if err != nil {
		return nil, errOperationLease
	}
	opened, err := directory.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = directory.Close()
		return nil, errOperationLease
	}
	name := path.Join(dir, op+".lock")
	f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		_ = directory.Close()
		return nil, errOperationLease
	}
	if syncOperationDir(root, dir) != nil {
		_ = f.Close()
		_ = directory.Close()
		return nil, errOperationLease
	}
	release, err := filelease.Acquire(ctx, f, true)
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	l := &operationLease{root: root, file: f, directory: directory, name: name, release: release}
	if err = l.Check(ctx); err != nil {
		l.Release()
		return nil, err
	}
	return l, nil
}

func (l *operationLease) Check(ctx context.Context) error {
	if l == nil || l.file == nil || l.directory == nil || ctx == nil || ctx.Err() != nil {
		return errOperationLease
	}
	parent, err := l.directory.Stat()
	if err != nil {
		return errOperationLease
	}
	currentParent, err := l.root.Lstat(path.Dir(l.name))
	if err != nil || !currentParent.IsDir() || !os.SameFile(parent, currentParent) {
		return errOperationLease
	}
	held, err := l.file.Stat()
	if err != nil || !held.Mode().IsRegular() || held.Mode().Perm() != 0600 {
		return errOperationLease
	}
	st, ok := held.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
		return errOperationLease
	}
	current, err := l.root.Lstat(l.name)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(held, current) {
		return errOperationLease
	}
	return nil
}

func (l *operationLease) Release() {
	if l != nil {
		l.once.Do(func() { l.release(); _ = l.directory.Close() })
	}
}

// RunOperationStaged keeps the real policy lease and the per-operation
// cross-process lease through staging, publication, and stage cleanup. The
// caller must authenticate the capability first. The immutable encrypted
// Owner intent is synced before any stage write; this is not a product route.
// stage returns a synchronous cleanup for its open files. Neither callback may
// leave background writers; publication must also check its own context at
// the irreversible mutation. An ambiguous publication must be reconciled.
func RunOperationStaged(ctx context.Context, policy store.OwnerControlLease, deadline ReadDeadline, body io.ReadCloser, maximum time.Duration, root *os.Root, v *vault.Vault, claim protocol.SelectedStorageUpload, requireExisting bool, stage func(context.Context) (func(), error), publish func(context.Context) error) error {
	if stage == nil || publish == nil || root == nil || v == nil || !validOperationID(claim.OperationID) {
		if policy != nil {
			policy.Release()
		}
		return errOperationLease
	}
	return RunStream(ctx, policy, deadline, body, maximum, func(c context.Context) error {
		operation, err := acquireOperationLease(c, root, claim.OperationID)
		if err != nil {
			return err
		}
		defer operation.Release()
		if err = persistOwnerIntent(c, root, v, claim, requireExisting, false); err != nil {
			return err
		}
		cleanup, err := stage(c)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			return err
		}
		if err = operation.Check(c); err != nil {
			return err
		}
		if err = policy.Check(c); err != nil {
			return err
		}
		if err = c.Err(); err != nil {
			return err
		}
		return publish(c)
	})
}

// RunOperationCleanup requires a separately verified Master cleanup ticket.
// It serializes behind all writers, durably records the cancellation tombstone
// first, then removes only the two opaque paths for this exact intent. Failure
// leaves the tombstone and Master reservation for safe reconciliation.
func RunOperationCleanup(ctx context.Context, policy store.OwnerControlLease, deadline ReadDeadline, body io.ReadCloser, maximum time.Duration, root *os.Root, v *vault.Vault, claim protocol.SelectedStorageUpload, sign func(context.Context) error) error {
	return RunOperationCleanupGuarded(ctx, policy, deadline, body, maximum, root, v, claim, nil, sign)
}

// RunOperationCleanupGuarded runs beforeRemove after durable cancellation and
// before unlinking, under the same policy and cross-process operation leases.
func RunOperationCleanupGuarded(ctx context.Context, policy store.OwnerControlLease, deadline ReadDeadline, body io.ReadCloser, maximum time.Duration, root *os.Root, v *vault.Vault, claim protocol.SelectedStorageUpload, beforeRemove, sign func(context.Context) error) error {
	if root == nil || v == nil || sign == nil || !validOperationID(claim.OperationID) {
		if policy != nil {
			policy.Release()
		}
		return errOperationLease
	}
	return RunStream(ctx, policy, deadline, body, maximum, func(c context.Context) error {
		operation, err := acquireOperationLease(c, root, claim.OperationID)
		if err != nil {
			return err
		}
		defer operation.Release()
		if err = markOwnerCancelled(c, root, v, claim); err != nil {
			return err
		}
		if beforeRemove != nil {
			if err = operation.Check(c); err != nil {
				return err
			}
			if err = policy.Check(c); err != nil {
				return err
			}
			if err = beforeRemove(c); err != nil {
				return err
			}
		}
		blob, err := sealedtree.BlobPath(claim.ObjectID)
		if err != nil {
			return errOperationLease
		}
		for _, name := range []string{path.Join("staging", claim.OperationID+".part"), blob} {
			if err = operation.Check(c); err != nil {
				return err
			}
			if err = policy.Check(c); err != nil {
				return err
			}
			digest, size := "", int64(0)
			if name == blob {
				digest, size = claim.ContentSHA256, claim.Size
			}
			if err = removeOperationPath(c, root, name, digest, size); err != nil {
				return err
			}
		}
		if err = operation.Check(c); err != nil {
			return err
		}
		if err = policy.Check(c); err != nil {
			return err
		}
		if err = c.Err(); err != nil {
			return err
		}
		return sign(c)
	})
}
