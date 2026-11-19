//go:build linux

package selectedupload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"golang.org/x/sys/unix"
)

// CleanupBlobProof is an ephemeral, pinned descriptor produced by hashing an
// exact opaque blob. It is not authorization to delete, an Owner signature,
// or proof against a malicious Master host. The final guarded cleanup must
// hold the matching Owner, media-volume and per-operation leases; all project
// writers of this inode must respect those leases.
type CleanupBlobProof struct {
	mu        sync.Mutex
	root      *os.Root
	parent    *os.File
	file      *os.File
	name      string
	leaf      string
	operation string
	blob      string
	digest    string
	size      int64
	stat      unix.Stat_t
	closed    bool
	used      bool
}

// ErrCleanupBlobMissing means the no-follow blob path was absent at prehash.
// It is not proof of successful deletion; the guarded Owner operation must
// still authenticate the durable operation and create/check its tombstone.
var ErrCleanupBlobMissing = errors.New("cleanup blob missing")

// CleanupMediaLease must be a genuine exclusive lease for the exact Owner
// volume, acquired after the Owner fence. Implementations are trusted runtime
// dependencies, not data supplied by an HTTP caller.
type CleanupMediaLease interface {
	CheckCleanupRoot(context.Context, *os.Root) error
}

// RunOperationCleanupWithProof is an unregistered guarded cleanup for a
// Master-authorized deletion. It preserves the Owner cancellation tombstone
// and signature ordering of the existing cleanup while avoiding an expensive
// second hash inside the Owner lease. A nil proof is allowed only when the
// final blob is already absent, for retry after a previous unlink. The caller
// must also retain a real exclusive media-volume lease through this call.
func RunOperationCleanupWithProof(ctx context.Context, policy store.OwnerControlLease, media CleanupMediaLease, deadline ReadDeadline, body io.ReadCloser, maximum time.Duration, root *os.Root, v *vault.Vault, claim protocol.SelectedStorageUpload, proof *CleanupBlobProof, authorize, sign func(context.Context) error) error {
	if root == nil || v == nil || media == nil || authorize == nil || sign == nil || !validOperationID(claim.OperationID) {
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
		if operation.Check(c) != nil || policy.Check(c) != nil || media.CheckCleanupRoot(c, root) != nil || authorize(c) != nil {
			return errOperationLease
		}
		name, err := sealedtree.BlobPath(claim.ObjectID)
		if err != nil {
			return errOperationLease
		}
		if proof == nil {
			parent, leaf, e := operationParent(root, name)
			if e == nil {
				var stat unix.Stat_t
				e = unix.Fstatat(int(parent.Fd()), leaf, &stat, unix.AT_SYMLINK_NOFOLLOW)
				parent.Close()
			}
			if !errors.Is(e, unix.ENOENT) {
				return errOperationLease
			}
		} else {
			proof.mu.Lock()
			err = proof.check(c, root, claim)
			proof.mu.Unlock()
			if err != nil {
				return errOperationLease
			}
		}
		if err = markOwnerCancelled(c, root, v, claim); err != nil {
			return err
		}
		if operation.Check(c) != nil || policy.Check(c) != nil || media.CheckCleanupRoot(c, root) != nil || authorize(c) != nil {
			return errOperationLease
		}
		if proof != nil {
			if err = proof.unlink(c, root, claim); err != nil {
				return err
			}
		}
		if err = removeOperationPath(c, root, path.Join("staging", claim.OperationID+".part"), "", 0); err != nil {
			return err
		}
		if operation.Check(c) != nil || policy.Check(c) != nil || media.CheckCleanupRoot(c, root) != nil || authorize(c) != nil || c.Err() != nil {
			return errOperationLease
		}
		return sign(c)
	})
}

func sameCleanupStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim && a.Nlink == b.Nlink && a.Mode&unix.S_IFMT == unix.S_IFREG
}

// PrepareCleanupBlob performs the expensive, bounded-memory hash without an
// Owner lease. A successful proof keeps the exact no-follow file and parent
// descriptors open; any normal content, inode, link or metadata modification
// detected before cleanup invalidates it. Call Close on every path.
func PrepareCleanupBlob(ctx context.Context, root *os.Root, claim protocol.SelectedStorageUpload) (*CleanupBlobProof, error) {
	if ctx == nil || root == nil || ctx.Err() != nil || !validOperationID(claim.OperationID) || !validOperationID(claim.ObjectID) || !validOperationID(claim.ContentSHA256) || claim.Size <= 0 || claim.Size > 10*store.GiB {
		return nil, errOperationLease
	}
	name, err := sealedtree.BlobPath(claim.ObjectID)
	if err != nil {
		return nil, errOperationLease
	}
	parent, leaf, err := operationParent(root, name)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, ErrCleanupBlobMissing
		}
		return nil, errOperationLease
	}
	fd, err := unix.Openat(int(parent.Fd()), leaf, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		parent.Close()
		if errors.Is(err, unix.ENOENT) {
			return nil, ErrCleanupBlobMissing
		}
		return nil, errOperationLease
	}
	file := os.NewFile(uintptr(fd), leaf)
	p := &CleanupBlobProof{root: root, parent: parent, file: file, name: name, leaf: leaf, operation: claim.OperationID, blob: claim.ObjectID, digest: claim.ContentSHA256, size: claim.Size}
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size != claim.Size {
		p.Close()
		return nil, errOperationLease
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, io.LimitReader(&cancelReader{ctx: ctx, source: file}, claim.Size+1), make([]byte, 64<<10))
	if err != nil || n != claim.Size || hex.EncodeToString(hash.Sum(nil)) != claim.ContentSHA256 || unix.Fstat(fd, &after) != nil || !sameCleanupStat(before, after) || ctx.Err() != nil {
		p.Close()
		return nil, errOperationLease
	}
	p.stat = after
	if err = p.check(ctx, root, claim); err != nil {
		p.Close()
		return nil, errOperationLease
	}
	return p, nil
}

// check is called only while p.mu is held by cleanup or before publication.
func (p *CleanupBlobProof) check(ctx context.Context, root *os.Root, claim protocol.SelectedStorageUpload) error {
	if p == nil || p.closed || p.used || p.file == nil || p.parent == nil || ctx == nil || ctx.Err() != nil || root != p.root || claim.OperationID != p.operation || claim.ObjectID != p.blob || claim.ContentSHA256 != p.digest || claim.Size != p.size {
		return errOperationLease
	}
	var opened, named unix.Stat_t
	if unix.Fstat(int(p.file.Fd()), &opened) != nil || unix.Fstatat(int(p.parent.Fd()), p.leaf, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameCleanupStat(p.stat, opened) || !sameCleanupStat(opened, named) {
		return errOperationLease
	}
	current, leaf, err := operationParent(root, p.name)
	if err != nil || leaf != p.leaf {
		if current != nil {
			current.Close()
		}
		return errOperationLease
	}
	defer current.Close()
	a, e1 := p.parent.Stat()
	b, e2 := current.Stat()
	if e1 != nil || e2 != nil || !os.SameFile(a, b) || ctx.Err() != nil {
		return errOperationLease
	}
	return nil
}

func (p *CleanupBlobProof) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	var err error
	if p.file != nil {
		err = p.file.Close()
	}
	if p.parent != nil {
		if e := p.parent.Close(); err == nil {
			err = e
		}
	}
	return err
}

// unlink is only used by the guarded cleanup below, after the independent
// Owner, media-volume and operation fences have all been checked. The proof
// is consumed even on failure. A crash after unlink is reconciled from the
// durable Owner cancellation tombstone; it is never reported as a success here.
func (p *CleanupBlobProof) unlink(ctx context.Context, root *os.Root, claim protocol.SelectedStorageUpload) error {
	if p == nil {
		return errOperationLease
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.check(ctx, root, claim); err != nil {
		return errOperationLease
	}
	p.used = true
	if unix.Unlinkat(int(p.parent.Fd()), p.leaf, 0) != nil || p.parent.Sync() != nil || ctx.Err() != nil {
		return errOperationLease
	}
	current, leaf, err := operationParent(root, p.name)
	if err != nil || leaf != p.leaf {
		if current != nil {
			current.Close()
		}
		return errOperationLease
	}
	defer current.Close()
	a, e1 := p.parent.Stat()
	b, e2 := current.Stat()
	if e1 != nil || e2 != nil || !os.SameFile(a, b) || ctx.Err() != nil {
		return errOperationLease
	}
	return nil
}
