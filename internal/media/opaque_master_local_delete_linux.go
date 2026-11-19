//go:build linux

package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"golang.org/x/sys/unix"
)

type opaqueMasterLocalDeleteKey struct {
	Operation string `json:"operation"`
	Object    string `json:"object"`
	Native    string `json:"native"`
	Owner     string `json:"owner"`
	Blob      string `json:"blob"`
	Revision  string `json:"revision"`
}

type opaqueMasterLocalDeleteFile struct {
	Device      uint64 `json:"device"`
	Inode       uint64 `json:"inode"`
	ChangeSec   int64  `json:"change_sec"`
	ChangeNanos int64  `json:"change_nanos"`
}

type opaqueMasterLocalDeleteIntent struct {
	Key          opaqueMasterLocalDeleteKey  `json:"key"`
	OwnerBinding string                      `json:"owner_binding"`
	ParentDevice uint64                      `json:"parent_device"`
	ParentInode  uint64                      `json:"parent_inode"`
	File         opaqueMasterLocalDeleteFile `json:"file"`
}

// OpaqueMasterLocalDeleteProof pins a local directory and, when present,
// exactly one verified ciphertext inode. It is neither durable nor authority.
type OpaqueMasterLocalDeleteProof struct {
	mu          sync.Mutex
	volume      *os.Root
	parent      *opaqueBlobParent
	dir         *os.File
	file        *os.File
	info        os.FileInfo
	key         opaqueMasterLocalDeleteKey
	releaseRead func()
}

func masterLocalDeleteKey(operation string, p sealedtree.Placement) (opaqueMasterLocalDeleteKey, error) {
	if !operationID.MatchString(operation) || !ownedObjectID.MatchString(p.ObjectID) || !ownedObjectID.MatchString(p.NativeObjectID) ||
		!operationID.MatchString(p.OwnerID) || p.State != "active" || p.Encryption == nil || p.Bytes <= 0 ||
		p.BlobID == p.ObjectID || p.BlobID == p.NativeObjectID || p.ReadAlias == p.ObjectID || p.ReadAlias == p.NativeObjectID {
		return opaqueMasterLocalDeleteKey{}, store.ErrNodeState
	}
	revision, err := protocol.OpaquePlacementRevision(p.ReadAlias, p.BlobID, p.SHA256, p.Bytes, p.Encryption)
	if err != nil {
		return opaqueMasterLocalDeleteKey{}, store.ErrNodeState
	}
	return opaqueMasterLocalDeleteKey{Operation: operation, Object: p.ObjectID, Native: p.NativeObjectID, Owner: p.OwnerID, Blob: p.BlobID, Revision: revision}, nil
}

// PrepareOpaqueMasterLocalDeletion hashes only ciphertext with bounded memory.
// The trusted caller passes its committed intent snapshot and holds no Owner,
// tree or volume mutation lease during this scan. An absent file still needs the
// exact durable Owner intent in DeleteOpaqueMasterLocalBlob. Always Close.
func (s *Service) PrepareOpaqueMasterLocalDeletion(ctx context.Context, operation string, p sealedtree.Placement) (*OpaqueMasterLocalDeleteProof, error) {
	key, err := masterLocalDeleteKey(operation, p)
	if err != nil || s == nil || s.root == nil || s.identity == nil || s.identity.ID != key.Owner || ctx == nil {
		return nil, store.ErrNodeState
	}
	readSlot, err := s.acquirePlainRead(ctx)
	if err != nil {
		return nil, err
	}
	parent, err := openOpaqueBlobParent(s.root, key.Blob)
	if err != nil {
		readSlot()
		return nil, err
	}
	proof := &OpaqueMasterLocalDeleteProof{volume: s.root, parent: parent, key: key, releaseRead: readSlot}
	fail := func(err error) (*OpaqueMasterLocalDeleteProof, error) {
		_ = proof.Close()
		return nil, err
	}
	proof.dir, err = parent.Leaf().Open(".")
	if err != nil {
		return fail(store.ErrNodeState)
	}
	name := key.Blob + ".blob"
	info, err := parent.Leaf().Lstat(name)
	if !errors.Is(err, os.ErrNotExist) {
		if err != nil || !info.Mode().IsRegular() || !opaqueSingleLink(info) || info.Size() != p.Bytes {
			return fail(store.ErrNodeState)
		}
		fd, err := unix.Openat(int(proof.dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return fail(store.ErrNodeState)
		}
		proof.file, proof.info = os.NewFile(uintptr(fd), name), info
		opened, err := proof.file.Stat()
		if err != nil || !sameRecoveryOpaqueFile(info, opened) {
			return fail(store.ErrNodeState)
		}
		h := sha256.New()
		n, err := io.CopyBuffer(h, io.LimitReader(&contextReader{ctx, proof.file}, p.Bytes+1), make([]byte, 64<<10))
		if err != nil || n != p.Bytes || hex.EncodeToString(h.Sum(nil)) != p.SHA256 {
			return fail(store.ErrNodeState)
		}
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if proof.checkFile() != nil {
		return fail(store.ErrNodeState)
	}
	return proof, nil
}

func (p *OpaqueMasterLocalDeleteProof) checkFile() error {
	if p.parent == nil || p.parent.Check() != nil {
		return store.ErrNodeState
	}
	current, err := p.parent.Leaf().Lstat(p.key.Blob + ".blob")
	if p.file == nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return store.ErrNodeState
	}
	opened, statErr := p.file.Stat()
	if err != nil || statErr != nil || !sameRecoveryOpaqueFile(p.info, current) || !sameRecoveryOpaqueFile(p.info, opened) {
		return store.ErrNodeState
	}
	return nil
}

func (p *OpaqueMasterLocalDeleteProof) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.parent == nil {
		return nil
	}
	p.parent.Close()
	p.parent = nil
	p.releaseRead()
	var err error
	if p.dir != nil {
		err = p.dir.Close()
	}
	if p.file != nil {
		err = errors.Join(err, p.file.Close())
	}
	return err
}

type preparedMasterLocalMediaDelete struct {
	*OpaqueMasterLocalDeleteProof
	service   *Service
	operation string
	placement sealedtree.Placement
}

// PrepareOpaqueMasterLocalMediaDelete adapts the pinned proof to the trusted
// Master coordinator without exposing a filesystem locator or callback to HTTP.
func (s *Service) PrepareOpaqueMasterLocalMediaDelete(ctx context.Context, op string, p sealedtree.Placement) (sealedtree.MasterLocalDeletePrepared, error) {
	if p.Encryption != nil {
		copy := *p.Encryption
		p.Encryption = &copy
	}
	proof, err := s.PrepareOpaqueMasterLocalDeletion(ctx, op, p)
	if err != nil {
		return nil, err
	}
	return &preparedMasterLocalMediaDelete{OpaqueMasterLocalDeleteProof: proof, service: s, operation: op, placement: p}, nil
}

func (p *preparedMasterLocalMediaDelete) Delete(ctx context.Context, owner store.OwnerControlLease, authorize func(context.Context) error) error {
	return p.service.DeleteOpaqueMasterLocalBlob(ctx, owner, p.operation, p.placement, p.OpaqueMasterLocalDeleteProof, authorize)
}

// DeleteOpaqueMasterLocalBlob requires the actual Owner lease and a trusted
// callback that checks the exact committed Master intent under the caller's
// ingress/tree authority. The callback must not acquire a new Owner, tree or
// volume lease. The volume write lease is nonblocking so already admitted
// readers can finish. Only an authenticated, durable pre-unlink intent can
// explain absence on retry. The returned success covers one linked file.
func (s *Service) DeleteOpaqueMasterLocalBlob(ctx context.Context, owner store.OwnerControlLease, operation string, p sealedtree.Placement, proof *OpaqueMasterLocalDeleteProof, authorize func(context.Context) error) error {
	key, err := masterLocalDeleteKey(operation, p)
	if err != nil || s == nil || proof == nil {
		return store.ErrNodeState
	}
	proof.mu.Lock()
	defer proof.mu.Unlock()
	if proof.volume != s.root || proof.key != key || proof.parent == nil {
		return store.ErrNodeState
	}
	return s.withMasterLocalDeleteVolume(ctx, owner, key.Owner, authorize, func(binding string, check func() error) error {
		return s.removeMasterLocalDeleteProof(ctx, key, proof, authorize, binding, check)
	})
}

func (s *Service) withMasterLocalDeleteVolume(ctx context.Context, owner store.OwnerControlLease, ownerID string, authorize func(context.Context) error, apply func(string, func() error) error) error {
	if s == nil || s.root == nil || s.identity == nil || ctx == nil || !recoveryValuePresent(owner) || authorize == nil {
		return store.ErrNodeState
	}
	observer, ok := s.nodes.(recoveryOwnerMarker)
	if !ok || !recoveryValuePresent(s.nodes) || owner.Check(ctx) != nil {
		return store.ErrNodeState
	}
	binding, err := owner.Binding(ctx)
	if err != nil || !ownedObjectID.MatchString(binding) || observer.VerifyOwnerControlBinding(ctx, binding) != nil {
		return store.ErrNodeState
	}
	identity, err := s.nodes.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != ownerID || identity.ID != s.identity.ID {
		return store.ErrNodeState
	}
	if err := authorize(ctx); err != nil {
		return err
	}
	lockBefore, err := s.root.Lstat(".media-mutation.lock")
	if err != nil || !lockBefore.Mode().IsRegular() || lockBefore.Size() != 0 || !opaqueSingleLink(lockBefore) {
		return store.ErrNodeState
	}
	volume, err := s.TryRecordingCleanup(ctx)
	if err != nil {
		return err
	}
	defer volume.Release()
	rootInfo, err := s.root.Stat(".")
	if err != nil {
		return store.ErrNodeState
	}
	check := func() error {
		currentRoot, err := os.Lstat(s.root.Name())
		lockInfo, lockErr := s.root.Lstat(".media-mutation.lock")
		if err != nil || !currentRoot.IsDir() || !os.SameFile(rootInfo, currentRoot) || lockErr != nil ||
			!lockInfo.Mode().IsRegular() || !os.SameFile(lockBefore, lockInfo) || lockInfo.Size() != 0 || !opaqueSingleLink(lockInfo) || owner.Check(ctx) != nil ||
			volume.CheckCleanupRoot(ctx, s.root) != nil {
			return store.ErrNodeState
		}
		return nil
	}
	if s.ready() != nil || check() != nil || s.opaqueRegistryDir(false) != nil {
		return store.ErrNodeState
	}
	return apply(binding, check)
}

func (s *Service) removeMasterLocalDeleteProof(ctx context.Context, key opaqueMasterLocalDeleteKey, proof *OpaqueMasterLocalDeleteProof, authorize func(context.Context) error, binding string, volumeCheck func() error) error {
	check := func() error {
		if volumeCheck() != nil || proof.parent.Check() != nil {
			return store.ErrNodeState
		}
		return nil
	}
	if proof.checkFile() != nil {
		return store.ErrNodeState
	}
	parentInfo, err := proof.dir.Stat()
	currentParent, currentErr := proof.parent.Leaf().Stat(".")
	if err != nil || currentErr != nil || !os.SameFile(parentInfo, currentParent) {
		return store.ErrNodeState
	}
	device, inode, ok := opaqueDirectoryIdentity(parentInfo)
	if !ok {
		return store.ErrNodeState
	}
	wanted := opaqueMasterLocalDeleteIntent{Key: key, OwnerBinding: binding, ParentDevice: device, ParentInode: inode}
	if proof.info != nil {
		info, ok := proof.info.Sys().(*syscall.Stat_t)
		if !ok || info.Nlink != 1 {
			return store.ErrNodeState
		}
		wanted.File = opaqueMasterLocalDeleteFile{Device: uint64(info.Dev), Inode: info.Ino, ChangeSec: int64(info.Ctim.Sec), ChangeNanos: int64(info.Ctim.Nsec)}
	}
	journal := opaqueRegistryFile(key.Blob, ".master-local-delete")
	var previous opaqueMasterLocalDeleteIntent
	err = s.readOpaqueRecord(journal, &previous)
	if err == nil {
		if proof.file == nil {
			wanted.File = previous.File
		}
		if previous != wanted || previous.File.Inode == 0 {
			return store.ErrNodeState
		}
	} else if !errors.Is(err, os.ErrNotExist) || proof.file == nil {
		return store.ErrNodeState
	} else if err = s.publishOpaqueMasterLocalDeleteIntent(journal, wanted); err != nil {
		return err
	}
	// Also sync an existing journal. It may have survived a crash during
	// publication before its directory entry was acknowledged as durable.
	if s.syncDirectory(opaqueRegistryDirectory) != nil {
		return store.ErrNodeState
	}
	if err = authorize(ctx); err != nil {
		return err
	}
	if check() != nil || proof.checkFile() != nil {
		return store.ErrNodeState
	}
	leaf, name := proof.parent.Leaf(), key.Blob+".blob"
	if proof.file != nil {
		if err = unix.Unlinkat(int(proof.dir.Fd()), name, 0); err != nil {
			return err
		}
	}
	if _, err = leaf.Lstat(name); !errors.Is(err, os.ErrNotExist) || proof.dir.Sync() != nil || check() != nil {
		return store.ErrNodeState
	}
	return authorize(ctx)
}

// Publish a fully synced, authenticated journal without overwriting one.
// A crash before rename can leave only the private per-blob preparation file;
// the exact retry reclaims it while holding the same exclusive volume lease.
func (s *Service) publishOpaqueMasterLocalDeleteIntent(name string, intent opaqueMasterLocalDeleteIntent) error {
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	sealed, err := s.identity.SealOpaqueOwnerRecord(name, raw)
	if err != nil {
		return err
	}
	temp := name + ".prepare"
	if info, err := s.root.Lstat(temp); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !opaqueSingleLink(info) || s.root.Remove(temp) != nil {
			return store.ErrNodeState
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := s.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.WriteString(sealed)
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || n != len(sealed) || syncErr != nil || closeErr != nil {
		_ = s.root.Remove(temp)
		return store.ErrNodeState
	}
	if err = s.renameExclusive(temp, name); err != nil {
		_ = s.root.Remove(temp)
		return err
	}
	return nil
}
